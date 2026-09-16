rule TTP_XOR_QUAD_CurrentVersionRun_776e {
  strings:
    $key_776e = { 24 01 [2] 00 0f [2] 2b 23 [2] 05 01 [2] 11 1a [2] 1e 00 [2] 00 1d [2] 02 1c [2] 19 1a [2] 05 1d [2] 19 32 }

  condition:
    any of them
}