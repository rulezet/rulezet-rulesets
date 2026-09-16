rule TTP_XOR_QUAD_CurrentVersionRun_450b {
  strings:
    $key_450b = { 16 64 [2] 32 6a [2] 19 46 [2] 37 64 [2] 23 7f [2] 2c 65 [2] 32 78 [2] 30 79 [2] 2b 7f [2] 37 78 [2] 2b 57 }

  condition:
    any of them
}