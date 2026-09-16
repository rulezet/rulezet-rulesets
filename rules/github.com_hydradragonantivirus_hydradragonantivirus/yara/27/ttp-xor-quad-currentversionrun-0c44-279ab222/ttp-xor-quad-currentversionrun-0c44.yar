rule TTP_XOR_QUAD_CurrentVersionRun_0c44 {
  strings:
    $key_0c44 = { 5f 2b [2] 7b 25 [2] 50 09 [2] 7e 2b [2] 6a 30 [2] 65 2a [2] 7b 37 [2] 79 36 [2] 62 30 [2] 7e 37 [2] 62 18 }

  condition:
    any of them
}