rule TTP_XOR_QUAD_CurrentVersionRun_452b {
  strings:
    $key_452b = { 16 44 [2] 32 4a [2] 19 66 [2] 37 44 [2] 23 5f [2] 2c 45 [2] 32 58 [2] 30 59 [2] 2b 5f [2] 37 58 [2] 2b 77 }

  condition:
    any of them
}