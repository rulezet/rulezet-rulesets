rule TTP_XOR_QUAD_CurrentVersionRun_5e7b {
  strings:
    $key_5e7b = { 0d 14 [2] 29 1a [2] 02 36 [2] 2c 14 [2] 38 0f [2] 37 15 [2] 29 08 [2] 2b 09 [2] 30 0f [2] 2c 08 [2] 30 27 }

  condition:
    any of them
}