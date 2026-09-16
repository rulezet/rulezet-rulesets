rule TTP_XOR_QUAD_CurrentVersionRun_dcbc {
  strings:
    $key_dcbc = { 8f d3 [2] ab dd [2] 80 f1 [2] ae d3 [2] ba c8 [2] b5 d2 [2] ab cf [2] a9 ce [2] b2 c8 [2] ae cf [2] b2 e0 }

  condition:
    any of them
}