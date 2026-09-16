rule TTP_XOR_QUAD_CurrentVersionRun_7c44 {
  strings:
    $key_7c44 = { 2f 2b [2] 0b 25 [2] 20 09 [2] 0e 2b [2] 1a 30 [2] 15 2a [2] 0b 37 [2] 09 36 [2] 12 30 [2] 0e 37 [2] 12 18 }

  condition:
    any of them
}