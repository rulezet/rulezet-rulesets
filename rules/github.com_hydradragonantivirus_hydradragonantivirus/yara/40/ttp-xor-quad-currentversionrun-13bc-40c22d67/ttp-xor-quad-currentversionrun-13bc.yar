rule TTP_XOR_QUAD_CurrentVersionRun_13bc {
  strings:
    $key_13bc = { 40 d3 [2] 64 dd [2] 4f f1 [2] 61 d3 [2] 75 c8 [2] 7a d2 [2] 64 cf [2] 66 ce [2] 7d c8 [2] 61 cf [2] 7d e0 }

  condition:
    any of them
}