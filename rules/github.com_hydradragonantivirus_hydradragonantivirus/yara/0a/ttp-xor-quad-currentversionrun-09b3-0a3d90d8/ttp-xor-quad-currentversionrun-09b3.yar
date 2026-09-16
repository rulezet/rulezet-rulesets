rule TTP_XOR_QUAD_CurrentVersionRun_09b3 {
  strings:
    $key_09b3 = { 5a dc [2] 7e d2 [2] 55 fe [2] 7b dc [2] 6f c7 [2] 60 dd [2] 7e c0 [2] 7c c1 [2] 67 c7 [2] 7b c0 [2] 67 ef }

  condition:
    any of them
}