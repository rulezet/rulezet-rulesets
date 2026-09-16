rule TTP_XOR_QUAD_CurrentVersionRun_c482 {
  strings:
    $key_c482 = { 97 ed [2] b3 e3 [2] 98 cf [2] b6 ed [2] a2 f6 [2] ad ec [2] b3 f1 [2] b1 f0 [2] aa f6 [2] b6 f1 [2] aa de }

  condition:
    any of them
}