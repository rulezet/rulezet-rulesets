rule TTP_XOR_QUAD_CurrentVersionRun_e5bc {
  strings:
    $key_e5bc = { b6 d3 [2] 92 dd [2] b9 f1 [2] 97 d3 [2] 83 c8 [2] 8c d2 [2] 92 cf [2] 90 ce [2] 8b c8 [2] 97 cf [2] 8b e0 }

  condition:
    any of them
}