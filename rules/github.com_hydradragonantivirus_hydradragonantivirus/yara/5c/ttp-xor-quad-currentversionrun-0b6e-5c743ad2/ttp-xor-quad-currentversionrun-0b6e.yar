rule TTP_XOR_QUAD_CurrentVersionRun_0b6e {
  strings:
    $key_0b6e = { 58 01 [2] 7c 0f [2] 57 23 [2] 79 01 [2] 6d 1a [2] 62 00 [2] 7c 1d [2] 7e 1c [2] 65 1a [2] 79 1d [2] 65 32 }

  condition:
    any of them
}