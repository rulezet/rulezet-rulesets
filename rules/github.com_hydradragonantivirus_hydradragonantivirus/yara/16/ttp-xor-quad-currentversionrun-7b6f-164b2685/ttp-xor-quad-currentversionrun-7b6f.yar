rule TTP_XOR_QUAD_CurrentVersionRun_7b6f {
  strings:
    $key_7b6f = { 28 00 [2] 0c 0e [2] 27 22 [2] 09 00 [2] 1d 1b [2] 12 01 [2] 0c 1c [2] 0e 1d [2] 15 1b [2] 09 1c [2] 15 33 }

  condition:
    any of them
}