rule TTP_XOR_QUAD_CurrentVersionRun_4979 {
  strings:
    $key_4979 = { 1a 16 [2] 3e 18 [2] 15 34 [2] 3b 16 [2] 2f 0d [2] 20 17 [2] 3e 0a [2] 3c 0b [2] 27 0d [2] 3b 0a [2] 27 25 }

  condition:
    any of them
}