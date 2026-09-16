rule TTP_XOR_QUAD_CurrentVersionRun_cebc {
  strings:
    $key_cebc = { 9d d3 [2] b9 dd [2] 92 f1 [2] bc d3 [2] a8 c8 [2] a7 d2 [2] b9 cf [2] bb ce [2] a0 c8 [2] bc cf [2] a0 e0 }

  condition:
    any of them
}