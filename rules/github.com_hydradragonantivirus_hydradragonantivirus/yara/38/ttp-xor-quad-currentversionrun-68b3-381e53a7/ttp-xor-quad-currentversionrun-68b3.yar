rule TTP_XOR_QUAD_CurrentVersionRun_68b3 {
  strings:
    $key_68b3 = { 3b dc [2] 1f d2 [2] 34 fe [2] 1a dc [2] 0e c7 [2] 01 dd [2] 1f c0 [2] 1d c1 [2] 06 c7 [2] 1a c0 [2] 06 ef }

  condition:
    any of them
}