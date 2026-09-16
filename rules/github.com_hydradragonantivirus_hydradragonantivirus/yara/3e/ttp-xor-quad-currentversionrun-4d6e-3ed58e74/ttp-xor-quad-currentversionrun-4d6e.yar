rule TTP_XOR_QUAD_CurrentVersionRun_4d6e {
  strings:
    $key_4d6e = { 1e 01 [2] 3a 0f [2] 11 23 [2] 3f 01 [2] 2b 1a [2] 24 00 [2] 3a 1d [2] 38 1c [2] 23 1a [2] 3f 1d [2] 23 32 }

  condition:
    any of them
}