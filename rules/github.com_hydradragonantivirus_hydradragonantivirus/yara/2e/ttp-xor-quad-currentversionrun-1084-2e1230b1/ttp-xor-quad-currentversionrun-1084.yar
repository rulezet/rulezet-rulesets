rule TTP_XOR_QUAD_CurrentVersionRun_1084 {
  strings:
    $key_1084 = { 43 eb [2] 67 e5 [2] 4c c9 [2] 62 eb [2] 76 f0 [2] 79 ea [2] 67 f7 [2] 65 f6 [2] 7e f0 [2] 62 f7 [2] 7e d8 }

  condition:
    any of them
}