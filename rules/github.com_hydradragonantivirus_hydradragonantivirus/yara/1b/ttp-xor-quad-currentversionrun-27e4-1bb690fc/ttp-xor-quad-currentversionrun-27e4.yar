rule TTP_XOR_QUAD_CurrentVersionRun_27e4 {
  strings:
    $key_27e4 = { 74 8b [2] 50 85 [2] 7b a9 [2] 55 8b [2] 41 90 [2] 4e 8a [2] 50 97 [2] 52 96 [2] 49 90 [2] 55 97 [2] 49 b8 }

  condition:
    any of them
}