rule TTP_XOR_QUAD_CurrentVersionRun_186e {
  strings:
    $key_186e = { 4b 01 [2] 6f 0f [2] 44 23 [2] 6a 01 [2] 7e 1a [2] 71 00 [2] 6f 1d [2] 6d 1c [2] 76 1a [2] 6a 1d [2] 76 32 }

  condition:
    any of them
}