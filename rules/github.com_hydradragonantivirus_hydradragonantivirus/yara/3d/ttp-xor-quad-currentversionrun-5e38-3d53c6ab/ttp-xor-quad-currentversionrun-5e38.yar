rule TTP_XOR_QUAD_CurrentVersionRun_5e38 {
  strings:
    $key_5e38 = { 0d 57 [2] 29 59 [2] 02 75 [2] 2c 57 [2] 38 4c [2] 37 56 [2] 29 4b [2] 2b 4a [2] 30 4c [2] 2c 4b [2] 30 64 }

  condition:
    any of them
}