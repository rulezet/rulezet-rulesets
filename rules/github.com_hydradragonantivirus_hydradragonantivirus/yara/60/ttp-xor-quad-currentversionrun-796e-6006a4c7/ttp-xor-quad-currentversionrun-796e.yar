rule TTP_XOR_QUAD_CurrentVersionRun_796e {
  strings:
    $key_796e = { 2a 01 [2] 0e 0f [2] 25 23 [2] 0b 01 [2] 1f 1a [2] 10 00 [2] 0e 1d [2] 0c 1c [2] 17 1a [2] 0b 1d [2] 17 32 }

  condition:
    any of them
}