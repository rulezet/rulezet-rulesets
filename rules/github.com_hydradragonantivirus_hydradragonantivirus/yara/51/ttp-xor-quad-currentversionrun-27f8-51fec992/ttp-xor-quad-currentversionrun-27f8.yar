rule TTP_XOR_QUAD_CurrentVersionRun_27f8 {
  strings:
    $key_27f8 = { 74 97 [2] 50 99 [2] 7b b5 [2] 55 97 [2] 41 8c [2] 4e 96 [2] 50 8b [2] 52 8a [2] 49 8c [2] 55 8b [2] 49 a4 }

  condition:
    any of them
}