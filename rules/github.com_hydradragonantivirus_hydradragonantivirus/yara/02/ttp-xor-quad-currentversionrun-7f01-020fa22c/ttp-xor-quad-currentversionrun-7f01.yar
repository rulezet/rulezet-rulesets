rule TTP_XOR_QUAD_CurrentVersionRun_7f01 {
  strings:
    $key_7f01 = { 2c 6e [2] 08 60 [2] 23 4c [2] 0d 6e [2] 19 75 [2] 16 6f [2] 08 72 [2] 0a 73 [2] 11 75 [2] 0d 72 [2] 11 5d }

  condition:
    any of them
}