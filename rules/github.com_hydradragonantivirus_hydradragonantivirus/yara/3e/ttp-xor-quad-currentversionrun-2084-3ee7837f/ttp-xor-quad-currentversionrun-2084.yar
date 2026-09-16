rule TTP_XOR_QUAD_CurrentVersionRun_2084 {
  strings:
    $key_2084 = { 73 eb [2] 57 e5 [2] 7c c9 [2] 52 eb [2] 46 f0 [2] 49 ea [2] 57 f7 [2] 55 f6 [2] 4e f0 [2] 52 f7 [2] 4e d8 }

  condition:
    any of them
}