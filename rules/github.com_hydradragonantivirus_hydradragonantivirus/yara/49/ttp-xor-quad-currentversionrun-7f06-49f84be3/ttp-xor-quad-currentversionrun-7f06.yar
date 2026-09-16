rule TTP_XOR_QUAD_CurrentVersionRun_7f06 {
  strings:
    $key_7f06 = { 2c 69 [2] 08 67 [2] 23 4b [2] 0d 69 [2] 19 72 [2] 16 68 [2] 08 75 [2] 0a 74 [2] 11 72 [2] 0d 75 [2] 11 5a }

  condition:
    any of them
}