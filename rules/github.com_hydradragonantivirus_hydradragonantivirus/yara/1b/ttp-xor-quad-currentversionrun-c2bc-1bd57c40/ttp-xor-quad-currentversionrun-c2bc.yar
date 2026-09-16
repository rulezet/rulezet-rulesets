rule TTP_XOR_QUAD_CurrentVersionRun_c2bc {
  strings:
    $key_c2bc = { 91 d3 [2] b5 dd [2] 9e f1 [2] b0 d3 [2] a4 c8 [2] ab d2 [2] b5 cf [2] b7 ce [2] ac c8 [2] b0 cf [2] ac e0 }

  condition:
    any of them
}