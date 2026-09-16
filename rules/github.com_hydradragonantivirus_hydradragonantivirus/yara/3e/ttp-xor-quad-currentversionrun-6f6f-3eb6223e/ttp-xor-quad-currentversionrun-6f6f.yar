rule TTP_XOR_QUAD_CurrentVersionRun_6f6f {
  strings:
    $key_6f6f = { 3c 00 [2] 18 0e [2] 33 22 [2] 1d 00 [2] 09 1b [2] 06 01 [2] 18 1c [2] 1a 1d [2] 01 1b [2] 1d 1c [2] 01 33 }

  condition:
    any of them
}