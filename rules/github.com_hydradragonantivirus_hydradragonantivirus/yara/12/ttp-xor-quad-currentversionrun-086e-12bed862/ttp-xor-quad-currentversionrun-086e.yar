rule TTP_XOR_QUAD_CurrentVersionRun_086e {
  strings:
    $key_086e = { 5b 01 [2] 7f 0f [2] 54 23 [2] 7a 01 [2] 6e 1a [2] 61 00 [2] 7f 1d [2] 7d 1c [2] 66 1a [2] 7a 1d [2] 66 32 }

  condition:
    any of them
}