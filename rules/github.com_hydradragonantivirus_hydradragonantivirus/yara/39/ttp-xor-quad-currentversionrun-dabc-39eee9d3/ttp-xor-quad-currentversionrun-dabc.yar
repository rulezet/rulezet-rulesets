rule TTP_XOR_QUAD_CurrentVersionRun_dabc {
  strings:
    $key_dabc = { 89 d3 [2] ad dd [2] 86 f1 [2] a8 d3 [2] bc c8 [2] b3 d2 [2] ad cf [2] af ce [2] b4 c8 [2] a8 cf [2] b4 e0 }

  condition:
    any of them
}