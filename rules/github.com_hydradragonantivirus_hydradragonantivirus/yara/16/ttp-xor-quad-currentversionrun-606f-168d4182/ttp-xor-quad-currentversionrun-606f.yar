rule TTP_XOR_QUAD_CurrentVersionRun_606f {
  strings:
    $key_606f = { 33 00 [2] 17 0e [2] 3c 22 [2] 12 00 [2] 06 1b [2] 09 01 [2] 17 1c [2] 15 1d [2] 0e 1b [2] 12 1c [2] 0e 33 }

  condition:
    any of them
}