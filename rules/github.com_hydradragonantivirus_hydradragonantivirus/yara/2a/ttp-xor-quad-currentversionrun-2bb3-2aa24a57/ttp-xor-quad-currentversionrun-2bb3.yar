rule TTP_XOR_QUAD_CurrentVersionRun_2bb3 {
  strings:
    $key_2bb3 = { 78 dc [2] 5c d2 [2] 77 fe [2] 59 dc [2] 4d c7 [2] 42 dd [2] 5c c0 [2] 5e c1 [2] 45 c7 [2] 59 c0 [2] 45 ef }

  condition:
    any of them
}