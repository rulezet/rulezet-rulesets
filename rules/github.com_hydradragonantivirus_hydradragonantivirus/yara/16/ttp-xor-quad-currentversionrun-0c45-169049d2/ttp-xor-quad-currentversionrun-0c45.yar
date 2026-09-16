rule TTP_XOR_QUAD_CurrentVersionRun_0c45 {
  strings:
    $key_0c45 = { 5f 2a [2] 7b 24 [2] 50 08 [2] 7e 2a [2] 6a 31 [2] 65 2b [2] 7b 36 [2] 79 37 [2] 62 31 [2] 7e 36 [2] 62 19 }

  condition:
    any of them
}