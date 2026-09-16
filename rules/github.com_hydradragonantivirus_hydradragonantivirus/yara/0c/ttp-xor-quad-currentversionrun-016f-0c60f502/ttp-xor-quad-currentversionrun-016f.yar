rule TTP_XOR_QUAD_CurrentVersionRun_016f {
  strings:
    $key_016f = { 52 00 [2] 76 0e [2] 5d 22 [2] 73 00 [2] 67 1b [2] 68 01 [2] 76 1c [2] 74 1d [2] 6f 1b [2] 73 1c [2] 6f 33 }

  condition:
    any of them
}