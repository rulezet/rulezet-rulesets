rule TTP_XOR_QUAD_CurrentVersionRun_29aa {
  strings:
    $key_29aa = { 7a c5 [2] 5e cb [2] 75 e7 [2] 5b c5 [2] 4f de [2] 40 c4 [2] 5e d9 [2] 5c d8 [2] 47 de [2] 5b d9 [2] 47 f6 }

  condition:
    any of them
}