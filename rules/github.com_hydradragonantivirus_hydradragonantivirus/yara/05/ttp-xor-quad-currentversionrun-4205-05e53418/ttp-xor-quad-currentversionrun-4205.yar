rule TTP_XOR_QUAD_CurrentVersionRun_4205 {
  strings:
    $key_4205 = { 11 6a [2] 35 64 [2] 1e 48 [2] 30 6a [2] 24 71 [2] 2b 6b [2] 35 76 [2] 37 77 [2] 2c 71 [2] 30 76 [2] 2c 59 }

  condition:
    any of them
}