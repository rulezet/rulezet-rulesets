rule TTP_XOR_QUAD_CurrentVersionRun_e4bc {
  strings:
    $key_e4bc = { b7 d3 [2] 93 dd [2] b8 f1 [2] 96 d3 [2] 82 c8 [2] 8d d2 [2] 93 cf [2] 91 ce [2] 8a c8 [2] 96 cf [2] 8a e0 }

  condition:
    any of them
}