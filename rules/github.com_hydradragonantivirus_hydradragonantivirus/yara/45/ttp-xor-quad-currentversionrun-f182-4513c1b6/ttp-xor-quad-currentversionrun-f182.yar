rule TTP_XOR_QUAD_CurrentVersionRun_f182 {
  strings:
    $key_f182 = { a2 ed [2] 86 e3 [2] ad cf [2] 83 ed [2] 97 f6 [2] 98 ec [2] 86 f1 [2] 84 f0 [2] 9f f6 [2] 83 f1 [2] 9f de }

  condition:
    any of them
}