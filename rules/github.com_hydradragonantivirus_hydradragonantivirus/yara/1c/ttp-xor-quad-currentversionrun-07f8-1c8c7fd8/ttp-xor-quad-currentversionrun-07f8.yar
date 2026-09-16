rule TTP_XOR_QUAD_CurrentVersionRun_07f8 {
  strings:
    $key_07f8 = { 54 97 [2] 70 99 [2] 5b b5 [2] 75 97 [2] 61 8c [2] 6e 96 [2] 70 8b [2] 72 8a [2] 69 8c [2] 75 8b [2] 69 a4 }

  condition:
    any of them
}