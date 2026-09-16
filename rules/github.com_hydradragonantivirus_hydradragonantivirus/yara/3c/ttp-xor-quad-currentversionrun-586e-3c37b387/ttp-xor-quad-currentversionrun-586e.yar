rule TTP_XOR_QUAD_CurrentVersionRun_586e {
  strings:
    $key_586e = { 0b 01 [2] 2f 0f [2] 04 23 [2] 2a 01 [2] 3e 1a [2] 31 00 [2] 2f 1d [2] 2d 1c [2] 36 1a [2] 2a 1d [2] 36 32 }

  condition:
    any of them
}