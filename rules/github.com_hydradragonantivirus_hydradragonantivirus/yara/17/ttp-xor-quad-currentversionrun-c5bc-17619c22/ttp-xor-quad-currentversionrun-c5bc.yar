rule TTP_XOR_QUAD_CurrentVersionRun_c5bc {
  strings:
    $key_c5bc = { 96 d3 [2] b2 dd [2] 99 f1 [2] b7 d3 [2] a3 c8 [2] ac d2 [2] b2 cf [2] b0 ce [2] ab c8 [2] b7 cf [2] ab e0 }

  condition:
    any of them
}