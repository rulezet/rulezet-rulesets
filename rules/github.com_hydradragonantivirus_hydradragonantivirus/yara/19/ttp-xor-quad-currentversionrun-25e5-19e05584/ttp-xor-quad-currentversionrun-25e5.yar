rule TTP_XOR_QUAD_CurrentVersionRun_25e5 {
  strings:
    $key_25e5 = { 76 8a [2] 52 84 [2] 79 a8 [2] 57 8a [2] 43 91 [2] 4c 8b [2] 52 96 [2] 50 97 [2] 4b 91 [2] 57 96 [2] 4b b9 }

  condition:
    any of them
}