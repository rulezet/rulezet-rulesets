rule TTP_XOR_QUAD_CurrentVersionRun_44bc {
  strings:
    $key_44bc = { 17 d3 [2] 33 dd [2] 18 f1 [2] 36 d3 [2] 22 c8 [2] 2d d2 [2] 33 cf [2] 31 ce [2] 2a c8 [2] 36 cf [2] 2a e0 }

  condition:
    any of them
}