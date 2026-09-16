rule TTP_XOR_QUAD_CurrentVersionRun_2bb5 {
  strings:
    $key_2bb5 = { 78 da [2] 5c d4 [2] 77 f8 [2] 59 da [2] 4d c1 [2] 42 db [2] 5c c6 [2] 5e c7 [2] 45 c1 [2] 59 c6 [2] 45 e9 }

  condition:
    any of them
}