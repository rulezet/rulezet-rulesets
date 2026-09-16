rule TTP_XOR_QUAD_CurrentVersionRun_6c6e {
  strings:
    $key_6c6e = { 3f 01 [2] 1b 0f [2] 30 23 [2] 1e 01 [2] 0a 1a [2] 05 00 [2] 1b 1d [2] 19 1c [2] 02 1a [2] 1e 1d [2] 02 32 }

  condition:
    any of them
}