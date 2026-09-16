rule TTP_XOR_QUAD_CurrentVersionRun_1b58 {
  strings:
    $key_1b58 = { 48 37 [2] 6c 39 [2] 47 15 [2] 69 37 [2] 7d 2c [2] 72 36 [2] 6c 2b [2] 6e 2a [2] 75 2c [2] 69 2b [2] 75 04 }

  condition:
    any of them
}