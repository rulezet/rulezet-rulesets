rule TTP_XOR_QUAD_CurrentVersionRun_5e05 {
  strings:
    $key_5e05 = { 0d 6a [2] 29 64 [2] 02 48 [2] 2c 6a [2] 38 71 [2] 37 6b [2] 29 76 [2] 2b 77 [2] 30 71 [2] 2c 76 [2] 30 59 }

  condition:
    any of them
}