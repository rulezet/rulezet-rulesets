rule TTP_XOR_QUAD_CurrentVersionRun_736e {
  strings:
    $key_736e = { 20 01 [2] 04 0f [2] 2f 23 [2] 01 01 [2] 15 1a [2] 1a 00 [2] 04 1d [2] 06 1c [2] 1d 1a [2] 01 1d [2] 1d 32 }

  condition:
    any of them
}