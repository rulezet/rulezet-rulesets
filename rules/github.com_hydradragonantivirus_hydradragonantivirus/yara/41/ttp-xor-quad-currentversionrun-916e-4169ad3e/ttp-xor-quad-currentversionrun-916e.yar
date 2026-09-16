rule TTP_XOR_QUAD_CurrentVersionRun_916e {
  strings:
    $key_916e = { c2 01 [2] e6 0f [2] cd 23 [2] e3 01 [2] f7 1a [2] f8 00 [2] e6 1d [2] e4 1c [2] ff 1a [2] e3 1d [2] ff 32 }

  condition:
    any of them
}