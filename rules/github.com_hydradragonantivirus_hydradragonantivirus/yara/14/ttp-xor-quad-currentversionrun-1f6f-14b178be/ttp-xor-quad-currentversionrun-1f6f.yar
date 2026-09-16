rule TTP_XOR_QUAD_CurrentVersionRun_1f6f {
  strings:
    $key_1f6f = { 4c 00 [2] 68 0e [2] 43 22 [2] 6d 00 [2] 79 1b [2] 76 01 [2] 68 1c [2] 6a 1d [2] 71 1b [2] 6d 1c [2] 71 33 }

  condition:
    any of them
}