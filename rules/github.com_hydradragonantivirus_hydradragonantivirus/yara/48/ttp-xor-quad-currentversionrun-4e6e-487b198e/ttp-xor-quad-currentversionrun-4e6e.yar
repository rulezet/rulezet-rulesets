rule TTP_XOR_QUAD_CurrentVersionRun_4e6e {
  strings:
    $key_4e6e = { 1d 01 [2] 39 0f [2] 12 23 [2] 3c 01 [2] 28 1a [2] 27 00 [2] 39 1d [2] 3b 1c [2] 20 1a [2] 3c 1d [2] 20 32 }

  condition:
    any of them
}