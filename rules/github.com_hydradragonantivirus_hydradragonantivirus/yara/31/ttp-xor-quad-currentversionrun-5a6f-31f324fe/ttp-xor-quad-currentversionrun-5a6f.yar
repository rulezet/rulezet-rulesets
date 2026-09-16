rule TTP_XOR_QUAD_CurrentVersionRun_5a6f {
  strings:
    $key_5a6f = { 09 00 [2] 2d 0e [2] 06 22 [2] 28 00 [2] 3c 1b [2] 33 01 [2] 2d 1c [2] 2f 1d [2] 34 1b [2] 28 1c [2] 34 33 }

  condition:
    any of them
}