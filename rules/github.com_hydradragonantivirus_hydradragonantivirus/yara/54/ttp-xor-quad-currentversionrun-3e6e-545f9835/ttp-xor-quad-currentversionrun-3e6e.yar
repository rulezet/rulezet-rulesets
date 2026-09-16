rule TTP_XOR_QUAD_CurrentVersionRun_3e6e {
  strings:
    $key_3e6e = { 6d 01 [2] 49 0f [2] 62 23 [2] 4c 01 [2] 58 1a [2] 57 00 [2] 49 1d [2] 4b 1c [2] 50 1a [2] 4c 1d [2] 50 32 }

  condition:
    any of them
}