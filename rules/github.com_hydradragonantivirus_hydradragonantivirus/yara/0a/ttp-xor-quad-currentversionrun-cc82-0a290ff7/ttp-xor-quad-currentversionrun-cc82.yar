rule TTP_XOR_QUAD_CurrentVersionRun_cc82 {
  strings:
    $key_cc82 = { 9f ed [2] bb e3 [2] 90 cf [2] be ed [2] aa f6 [2] a5 ec [2] bb f1 [2] b9 f0 [2] a2 f6 [2] be f1 [2] a2 de }

  condition:
    any of them
}