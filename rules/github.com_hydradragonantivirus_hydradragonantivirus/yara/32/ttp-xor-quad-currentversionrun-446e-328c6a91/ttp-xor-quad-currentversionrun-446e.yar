rule TTP_XOR_QUAD_CurrentVersionRun_446e {
  strings:
    $key_446e = { 17 01 [2] 33 0f [2] 18 23 [2] 36 01 [2] 22 1a [2] 2d 00 [2] 33 1d [2] 31 1c [2] 2a 1a [2] 36 1d [2] 2a 32 }

  condition:
    any of them
}