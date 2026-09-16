rule TTP_XOR_QUAD_CurrentVersionRun_d5a0 {
  strings:
    $key_d5a0 = { 86 cf [2] a2 c1 [2] 89 ed [2] a7 cf [2] b3 d4 [2] bc ce [2] a2 d3 [2] a0 d2 [2] bb d4 [2] a7 d3 [2] bb fc }

  condition:
    any of them
}