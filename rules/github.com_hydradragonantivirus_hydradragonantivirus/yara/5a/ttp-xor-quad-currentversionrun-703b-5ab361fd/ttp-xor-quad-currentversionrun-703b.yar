rule TTP_XOR_QUAD_CurrentVersionRun_703b {
  strings:
    $key_703b = { 23 54 [2] 07 5a [2] 2c 76 [2] 02 54 [2] 16 4f [2] 19 55 [2] 07 48 [2] 05 49 [2] 1e 4f [2] 02 48 [2] 1e 67 }

  condition:
    any of them
}