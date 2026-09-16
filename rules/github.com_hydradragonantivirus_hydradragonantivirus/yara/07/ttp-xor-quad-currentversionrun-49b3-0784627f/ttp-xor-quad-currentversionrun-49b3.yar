rule TTP_XOR_QUAD_CurrentVersionRun_49b3 {
  strings:
    $key_49b3 = { 1a dc [2] 3e d2 [2] 15 fe [2] 3b dc [2] 2f c7 [2] 20 dd [2] 3e c0 [2] 3c c1 [2] 27 c7 [2] 3b c0 [2] 27 ef }

  condition:
    any of them
}