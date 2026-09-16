rule TTP_XOR_QUAD_CurrentVersionRun_366e {
  strings:
    $key_366e = { 65 01 [2] 41 0f [2] 6a 23 [2] 44 01 [2] 50 1a [2] 5f 00 [2] 41 1d [2] 43 1c [2] 58 1a [2] 44 1d [2] 58 32 }

  condition:
    any of them
}