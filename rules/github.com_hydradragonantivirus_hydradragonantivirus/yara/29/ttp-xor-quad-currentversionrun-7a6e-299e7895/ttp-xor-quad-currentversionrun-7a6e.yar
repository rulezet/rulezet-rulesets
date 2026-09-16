rule TTP_XOR_QUAD_CurrentVersionRun_7a6e {
  strings:
    $key_7a6e = { 29 01 [2] 0d 0f [2] 26 23 [2] 08 01 [2] 1c 1a [2] 13 00 [2] 0d 1d [2] 0f 1c [2] 14 1a [2] 08 1d [2] 14 32 }

  condition:
    any of them
}