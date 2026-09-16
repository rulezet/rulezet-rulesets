rule TTP_XOR_QUAD_CurrentVersionRun_0cf9 {
  strings:
    $key_0cf9 = { 5f 96 [2] 7b 98 [2] 50 b4 [2] 7e 96 [2] 6a 8d [2] 65 97 [2] 7b 8a [2] 79 8b [2] 62 8d [2] 7e 8a [2] 62 a5 }

  condition:
    any of them
}