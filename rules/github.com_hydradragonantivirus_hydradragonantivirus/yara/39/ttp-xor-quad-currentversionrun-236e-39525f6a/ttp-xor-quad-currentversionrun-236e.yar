rule TTP_XOR_QUAD_CurrentVersionRun_236e {
  strings:
    $key_236e = { 70 01 [2] 54 0f [2] 7f 23 [2] 51 01 [2] 45 1a [2] 4a 00 [2] 54 1d [2] 56 1c [2] 4d 1a [2] 51 1d [2] 4d 32 }

  condition:
    any of them
}