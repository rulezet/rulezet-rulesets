rule TTP_XOR_QUAD_CurrentVersionRun_c4bc {
  strings:
    $key_c4bc = { 97 d3 [2] b3 dd [2] 98 f1 [2] b6 d3 [2] a2 c8 [2] ad d2 [2] b3 cf [2] b1 ce [2] aa c8 [2] b6 cf [2] aa e0 }

  condition:
    any of them
}