rule TTP_XOR_QUAD_CurrentVersionRun_e0bb {
  strings:
    $key_e0bb = { b3 d4 [2] 97 da [2] bc f6 [2] 92 d4 [2] 86 cf [2] 89 d5 [2] 97 c8 [2] 95 c9 [2] 8e cf [2] 92 c8 [2] 8e e7 }

  condition:
    any of them
}