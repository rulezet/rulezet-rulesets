rule TTP_XOR_QUAD_CurrentVersionRun_2f6e {
  strings:
    $key_2f6e = { 7c 01 [2] 58 0f [2] 73 23 [2] 5d 01 [2] 49 1a [2] 46 00 [2] 58 1d [2] 5a 1c [2] 41 1a [2] 5d 1d [2] 41 32 }

  condition:
    any of them
}