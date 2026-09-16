rule TTP_XOR_QUAD_CurrentVersionRun_f1bc {
  strings:
    $key_f1bc = { a2 d3 [2] 86 dd [2] ad f1 [2] 83 d3 [2] 97 c8 [2] 98 d2 [2] 86 cf [2] 84 ce [2] 9f c8 [2] 83 cf [2] 9f e0 }

  condition:
    any of them
}