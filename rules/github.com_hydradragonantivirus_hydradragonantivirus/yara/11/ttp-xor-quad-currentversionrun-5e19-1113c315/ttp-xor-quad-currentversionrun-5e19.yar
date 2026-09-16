rule TTP_XOR_QUAD_CurrentVersionRun_5e19 {
  strings:
    $key_5e19 = { 0d 76 [2] 29 78 [2] 02 54 [2] 2c 76 [2] 38 6d [2] 37 77 [2] 29 6a [2] 2b 6b [2] 30 6d [2] 2c 6a [2] 30 45 }

  condition:
    any of them
}