rule TTP_XOR_QUAD_CurrentVersionRun_e2bc {
  strings:
    $key_e2bc = { b1 d3 [2] 95 dd [2] be f1 [2] 90 d3 [2] 84 c8 [2] 8b d2 [2] 95 cf [2] 97 ce [2] 8c c8 [2] 90 cf [2] 8c e0 }

  condition:
    any of them
}