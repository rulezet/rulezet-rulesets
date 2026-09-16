rule TTP_XOR_QUAD_CurrentVersionRun_266e {
  strings:
    $key_266e = { 75 01 [2] 51 0f [2] 7a 23 [2] 54 01 [2] 40 1a [2] 4f 00 [2] 51 1d [2] 53 1c [2] 48 1a [2] 54 1d [2] 48 32 }

  condition:
    any of them
}