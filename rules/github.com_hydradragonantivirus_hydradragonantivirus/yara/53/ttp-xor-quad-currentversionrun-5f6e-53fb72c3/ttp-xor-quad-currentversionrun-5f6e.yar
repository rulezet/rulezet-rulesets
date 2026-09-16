rule TTP_XOR_QUAD_CurrentVersionRun_5f6e {
  strings:
    $key_5f6e = { 0c 01 [2] 28 0f [2] 03 23 [2] 2d 01 [2] 39 1a [2] 36 00 [2] 28 1d [2] 2a 1c [2] 31 1a [2] 2d 1d [2] 31 32 }

  condition:
    any of them
}