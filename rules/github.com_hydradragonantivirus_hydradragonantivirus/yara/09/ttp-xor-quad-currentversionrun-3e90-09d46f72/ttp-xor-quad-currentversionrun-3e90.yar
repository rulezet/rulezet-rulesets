rule TTP_XOR_QUAD_CurrentVersionRun_3e90 {
  strings:
    $key_3e90 = { 6d ff [2] 49 f1 [2] 62 dd [2] 4c ff [2] 58 e4 [2] 57 fe [2] 49 e3 [2] 4b e2 [2] 50 e4 [2] 4c e3 [2] 50 cc }

  condition:
    any of them
}