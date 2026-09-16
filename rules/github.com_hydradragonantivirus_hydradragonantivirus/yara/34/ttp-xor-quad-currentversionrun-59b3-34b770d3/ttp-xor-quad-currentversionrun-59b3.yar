rule TTP_XOR_QUAD_CurrentVersionRun_59b3 {
  strings:
    $key_59b3 = { 0a dc [2] 2e d2 [2] 05 fe [2] 2b dc [2] 3f c7 [2] 30 dd [2] 2e c0 [2] 2c c1 [2] 37 c7 [2] 2b c0 [2] 37 ef }

  condition:
    any of them
}