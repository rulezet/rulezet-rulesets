rule TTP_XOR_QUAD_CurrentVersionRun_7f7b {
  strings:
    $key_7f7b = { 2c 14 [2] 08 1a [2] 23 36 [2] 0d 14 [2] 19 0f [2] 16 15 [2] 08 08 [2] 0a 09 [2] 11 0f [2] 0d 08 [2] 11 27 }

  condition:
    any of them
}