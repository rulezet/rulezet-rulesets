rule TTP_XOR_QUAD_CurrentVersionRun_0ce5 {
  strings:
    $key_0ce5 = { 5f 8a [2] 7b 84 [2] 50 a8 [2] 7e 8a [2] 6a 91 [2] 65 8b [2] 7b 96 [2] 79 97 [2] 62 91 [2] 7e 96 [2] 62 b9 }

  condition:
    any of them
}