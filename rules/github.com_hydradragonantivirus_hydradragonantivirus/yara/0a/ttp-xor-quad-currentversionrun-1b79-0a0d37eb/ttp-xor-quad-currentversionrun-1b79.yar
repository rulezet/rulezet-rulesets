rule TTP_XOR_QUAD_CurrentVersionRun_1b79 {
  strings:
    $key_1b79 = { 48 16 [2] 6c 18 [2] 47 34 [2] 69 16 [2] 7d 0d [2] 72 17 [2] 6c 0a [2] 6e 0b [2] 75 0d [2] 69 0a [2] 75 25 }

  condition:
    any of them
}