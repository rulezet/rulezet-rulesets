rule TTP_XOR_QUAD_CurrentVersionRun_2e58 {
  strings:
    $key_2e58 = { 7d 37 [2] 59 39 [2] 72 15 [2] 5c 37 [2] 48 2c [2] 47 36 [2] 59 2b [2] 5b 2a [2] 40 2c [2] 5c 2b [2] 40 04 }

  condition:
    any of them
}