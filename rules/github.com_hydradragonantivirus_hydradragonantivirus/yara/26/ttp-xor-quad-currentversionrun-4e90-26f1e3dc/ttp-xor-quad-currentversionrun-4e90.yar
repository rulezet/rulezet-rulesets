rule TTP_XOR_QUAD_CurrentVersionRun_4e90 {
  strings:
    $key_4e90 = { 1d ff [2] 39 f1 [2] 12 dd [2] 3c ff [2] 28 e4 [2] 27 fe [2] 39 e3 [2] 3b e2 [2] 20 e4 [2] 3c e3 [2] 20 cc }

  condition:
    any of them
}