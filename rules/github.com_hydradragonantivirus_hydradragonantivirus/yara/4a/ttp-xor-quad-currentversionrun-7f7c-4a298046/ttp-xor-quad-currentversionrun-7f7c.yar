rule TTP_XOR_QUAD_CurrentVersionRun_7f7c {
  strings:
    $key_7f7c = { 2c 13 [2] 08 1d [2] 23 31 [2] 0d 13 [2] 19 08 [2] 16 12 [2] 08 0f [2] 0a 0e [2] 11 08 [2] 0d 0f [2] 11 20 }

  condition:
    any of them
}