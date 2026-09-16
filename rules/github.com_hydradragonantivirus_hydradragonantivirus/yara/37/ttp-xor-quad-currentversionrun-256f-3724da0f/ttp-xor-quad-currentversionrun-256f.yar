rule TTP_XOR_QUAD_CurrentVersionRun_256f {
  strings:
    $key_256f = { 76 00 [2] 52 0e [2] 79 22 [2] 57 00 [2] 43 1b [2] 4c 01 [2] 52 1c [2] 50 1d [2] 4b 1b [2] 57 1c [2] 4b 33 }

  condition:
    any of them
}