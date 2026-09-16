rule TTP_XOR_QUAD_CurrentVersionRun_26bc {
  strings:
    $key_26bc = { 75 d3 [2] 51 dd [2] 7a f1 [2] 54 d3 [2] 40 c8 [2] 4f d2 [2] 51 cf [2] 53 ce [2] 48 c8 [2] 54 cf [2] 48 e0 }

  condition:
    any of them
}