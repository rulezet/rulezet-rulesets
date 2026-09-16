rule TTP_XOR_QUAD_CurrentVersionRun_453b {
  strings:
    $key_453b = { 16 54 [2] 32 5a [2] 19 76 [2] 37 54 [2] 23 4f [2] 2c 55 [2] 32 48 [2] 30 49 [2] 2b 4f [2] 37 48 [2] 2b 67 }

  condition:
    any of them
}