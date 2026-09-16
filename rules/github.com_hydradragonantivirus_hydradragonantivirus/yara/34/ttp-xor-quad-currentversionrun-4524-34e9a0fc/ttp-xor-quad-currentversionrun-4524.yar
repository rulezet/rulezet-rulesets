rule TTP_XOR_QUAD_CurrentVersionRun_4524 {
  strings:
    $key_4524 = { 16 4b [2] 32 45 [2] 19 69 [2] 37 4b [2] 23 50 [2] 2c 4a [2] 32 57 [2] 30 56 [2] 2b 50 [2] 37 57 [2] 2b 78 }

  condition:
    any of them
}