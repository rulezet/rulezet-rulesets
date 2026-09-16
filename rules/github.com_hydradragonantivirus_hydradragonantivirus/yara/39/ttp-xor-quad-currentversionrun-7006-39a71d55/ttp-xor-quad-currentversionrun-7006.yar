rule TTP_XOR_QUAD_CurrentVersionRun_7006 {
  strings:
    $key_7006 = { 23 69 [2] 07 67 [2] 2c 4b [2] 02 69 [2] 16 72 [2] 19 68 [2] 07 75 [2] 05 74 [2] 1e 72 [2] 02 75 [2] 1e 5a }

  condition:
    any of them
}