rule TTP_XOR_QUAD_CurrentVersionRun_0c64 {
  strings:
    $key_0c64 = { 5f 0b [2] 7b 05 [2] 50 29 [2] 7e 0b [2] 6a 10 [2] 65 0a [2] 7b 17 [2] 79 16 [2] 62 10 [2] 7e 17 [2] 62 38 }

  condition:
    any of them
}