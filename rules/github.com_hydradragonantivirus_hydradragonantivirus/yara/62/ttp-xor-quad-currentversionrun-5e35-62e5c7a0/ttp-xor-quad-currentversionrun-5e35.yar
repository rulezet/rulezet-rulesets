rule TTP_XOR_QUAD_CurrentVersionRun_5e35 {
  strings:
    $key_5e35 = { 0d 5a [2] 29 54 [2] 02 78 [2] 2c 5a [2] 38 41 [2] 37 5b [2] 29 46 [2] 2b 47 [2] 30 41 [2] 2c 46 [2] 30 69 }

  condition:
    any of them
}