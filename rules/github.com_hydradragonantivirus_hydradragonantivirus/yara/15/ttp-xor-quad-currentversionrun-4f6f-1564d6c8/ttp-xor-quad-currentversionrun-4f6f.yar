rule TTP_XOR_QUAD_CurrentVersionRun_4f6f {
  strings:
    $key_4f6f = { 1c 00 [2] 38 0e [2] 13 22 [2] 3d 00 [2] 29 1b [2] 26 01 [2] 38 1c [2] 3a 1d [2] 21 1b [2] 3d 1c [2] 21 33 }

  condition:
    any of them
}