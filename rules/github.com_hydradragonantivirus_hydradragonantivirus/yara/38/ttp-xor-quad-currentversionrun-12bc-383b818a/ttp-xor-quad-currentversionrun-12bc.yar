rule TTP_XOR_QUAD_CurrentVersionRun_12bc {
  strings:
    $key_12bc = { 41 d3 [2] 65 dd [2] 4e f1 [2] 60 d3 [2] 74 c8 [2] 7b d2 [2] 65 cf [2] 67 ce [2] 7c c8 [2] 60 cf [2] 7c e0 }

  condition:
    any of them
}