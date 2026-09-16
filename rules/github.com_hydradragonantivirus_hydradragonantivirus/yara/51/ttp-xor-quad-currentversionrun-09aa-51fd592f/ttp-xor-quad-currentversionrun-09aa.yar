rule TTP_XOR_QUAD_CurrentVersionRun_09aa {
  strings:
    $key_09aa = { 5a c5 [2] 7e cb [2] 55 e7 [2] 7b c5 [2] 6f de [2] 60 c4 [2] 7e d9 [2] 7c d8 [2] 67 de [2] 7b d9 [2] 67 f6 }

  condition:
    any of them
}