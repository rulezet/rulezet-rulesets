rule TTP_XOR_QUAD_CurrentVersionRun_a6bc {
  strings:
    $key_a6bc = { f5 d3 [2] d1 dd [2] fa f1 [2] d4 d3 [2] c0 c8 [2] cf d2 [2] d1 cf [2] d3 ce [2] c8 c8 [2] d4 cf [2] c8 e0 }

  condition:
    any of them
}