rule TTP_XOR_QUAD_CurrentVersionRun_256e {
  strings:
    $key_256e = { 76 01 [2] 52 0f [2] 79 23 [2] 57 01 [2] 43 1a [2] 4c 00 [2] 52 1d [2] 50 1c [2] 4b 1a [2] 57 1d [2] 4b 32 }

  condition:
    any of them
}