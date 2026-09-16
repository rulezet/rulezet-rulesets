rule TTP_XOR_QUAD_CurrentVersionRun_336e {
  strings:
    $key_336e = { 60 01 [2] 44 0f [2] 6f 23 [2] 41 01 [2] 55 1a [2] 5a 00 [2] 44 1d [2] 46 1c [2] 5d 1a [2] 41 1d [2] 5d 32 }

  condition:
    any of them
}