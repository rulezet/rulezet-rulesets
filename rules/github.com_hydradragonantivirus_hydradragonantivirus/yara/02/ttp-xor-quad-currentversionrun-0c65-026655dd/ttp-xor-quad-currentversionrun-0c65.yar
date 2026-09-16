rule TTP_XOR_QUAD_CurrentVersionRun_0c65 {
  strings:
    $key_0c65 = { 5f 0a [2] 7b 04 [2] 50 28 [2] 7e 0a [2] 6a 11 [2] 65 0b [2] 7b 16 [2] 79 17 [2] 62 11 [2] 7e 16 [2] 62 39 }

  condition:
    any of them
}