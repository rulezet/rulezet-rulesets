rule TTP_XOR_QUAD_CurrentVersionRun_423b {
  strings:
    $key_423b = { 11 54 [2] 35 5a [2] 1e 76 [2] 30 54 [2] 24 4f [2] 2b 55 [2] 35 48 [2] 37 49 [2] 2c 4f [2] 30 48 [2] 2c 67 }

  condition:
    any of them
}