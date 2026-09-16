rule TTP_XOR_QUAD_CurrentVersionRun_0c78 {
  strings:
    $key_0c78 = { 5f 17 [2] 7b 19 [2] 50 35 [2] 7e 17 [2] 6a 0c [2] 65 16 [2] 7b 0b [2] 79 0a [2] 62 0c [2] 7e 0b [2] 62 24 }

  condition:
    any of them
}