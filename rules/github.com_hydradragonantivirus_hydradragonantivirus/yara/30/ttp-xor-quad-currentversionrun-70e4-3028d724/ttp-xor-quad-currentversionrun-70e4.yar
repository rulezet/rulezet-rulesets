rule TTP_XOR_QUAD_CurrentVersionRun_70e4 {
  strings:
    $key_70e4 = { 23 8b [2] 07 85 [2] 2c a9 [2] 02 8b [2] 16 90 [2] 19 8a [2] 07 97 [2] 05 96 [2] 1e 90 [2] 02 97 [2] 1e b8 }

  condition:
    any of them
}