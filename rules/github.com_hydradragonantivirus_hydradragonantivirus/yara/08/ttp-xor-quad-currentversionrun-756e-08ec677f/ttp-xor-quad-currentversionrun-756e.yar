rule TTP_XOR_QUAD_CurrentVersionRun_756e {
  strings:
    $key_756e = { 26 01 [2] 02 0f [2] 29 23 [2] 07 01 [2] 13 1a [2] 1c 00 [2] 02 1d [2] 00 1c [2] 1b 1a [2] 07 1d [2] 1b 32 }

  condition:
    any of them
}