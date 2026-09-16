rule TTP_XOR_QUAD_CurrentVersionRun_3bb4 {
  strings:
    $key_3bb4 = { 68 db [2] 4c d5 [2] 67 f9 [2] 49 db [2] 5d c0 [2] 52 da [2] 4c c7 [2] 4e c6 [2] 55 c0 [2] 49 c7 [2] 55 e8 }

  condition:
    any of them
}