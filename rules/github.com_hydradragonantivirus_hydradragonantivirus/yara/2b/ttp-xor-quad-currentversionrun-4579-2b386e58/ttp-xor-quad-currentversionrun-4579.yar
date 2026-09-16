rule TTP_XOR_QUAD_CurrentVersionRun_4579 {
  strings:
    $key_4579 = { 16 16 [2] 32 18 [2] 19 34 [2] 37 16 [2] 23 0d [2] 2c 17 [2] 32 0a [2] 30 0b [2] 2b 0d [2] 37 0a [2] 2b 25 }

  condition:
    any of them
}