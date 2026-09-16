rule TTP_XOR_QUAD_CurrentVersionRun_7f6e {
  strings:
    $key_7f6e = { 2c 01 [2] 08 0f [2] 23 23 [2] 0d 01 [2] 19 1a [2] 16 00 [2] 08 1d [2] 0a 1c [2] 11 1a [2] 0d 1d [2] 11 32 }

  condition:
    any of them
}