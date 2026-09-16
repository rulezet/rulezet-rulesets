rule TTP_XOR_QUAD_CurrentVersionRun_636e {
  strings:
    $key_636e = { 30 01 [2] 14 0f [2] 3f 23 [2] 11 01 [2] 05 1a [2] 0a 00 [2] 14 1d [2] 16 1c [2] 0d 1a [2] 11 1d [2] 0d 32 }

  condition:
    any of them
}