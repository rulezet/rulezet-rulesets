rule TTP_XOR_QUAD_CurrentVersionRun_726e {
  strings:
    $key_726e = { 21 01 [2] 05 0f [2] 2e 23 [2] 00 01 [2] 14 1a [2] 1b 00 [2] 05 1d [2] 07 1c [2] 1c 1a [2] 00 1d [2] 1c 32 }

  condition:
    any of them
}