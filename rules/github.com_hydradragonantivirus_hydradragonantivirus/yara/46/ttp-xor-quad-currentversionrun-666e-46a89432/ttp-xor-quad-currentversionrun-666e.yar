rule TTP_XOR_QUAD_CurrentVersionRun_666e {
  strings:
    $key_666e = { 35 01 [2] 11 0f [2] 3a 23 [2] 14 01 [2] 00 1a [2] 0f 00 [2] 11 1d [2] 13 1c [2] 08 1a [2] 14 1d [2] 08 32 }

  condition:
    any of them
}