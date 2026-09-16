rule TTP_XOR_QUAD_CurrentVersionRun_16bc {
  strings:
    $key_16bc = { 45 d3 [2] 61 dd [2] 4a f1 [2] 64 d3 [2] 70 c8 [2] 7f d2 [2] 61 cf [2] 63 ce [2] 78 c8 [2] 64 cf [2] 78 e0 }

  condition:
    any of them
}