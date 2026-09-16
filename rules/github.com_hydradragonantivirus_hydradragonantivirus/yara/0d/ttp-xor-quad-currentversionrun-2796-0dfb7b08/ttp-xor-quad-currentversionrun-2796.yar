rule TTP_XOR_QUAD_CurrentVersionRun_2796 {
  strings:
    $key_2796 = { 74 f9 [2] 50 f7 [2] 7b db [2] 55 f9 [2] 41 e2 [2] 4e f8 [2] 50 e5 [2] 52 e4 [2] 49 e2 [2] 55 e5 [2] 49 ca }

  condition:
    any of them
}