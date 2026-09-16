rule TTP_XOR_QUAD_CurrentVersionRun_4505 {
  strings:
    $key_4505 = { 16 6a [2] 32 64 [2] 19 48 [2] 37 6a [2] 23 71 [2] 2c 6b [2] 32 76 [2] 30 77 [2] 2b 71 [2] 37 76 [2] 2b 59 }

  condition:
    any of them
}