rule TTP_XOR_QUAD_CurrentVersionRun_45e4 {
  strings:
    $key_45e4 = { 16 8b [2] 32 85 [2] 19 a9 [2] 37 8b [2] 23 90 [2] 2c 8a [2] 32 97 [2] 30 96 [2] 2b 90 [2] 37 97 [2] 2b b8 }

  condition:
    any of them
}