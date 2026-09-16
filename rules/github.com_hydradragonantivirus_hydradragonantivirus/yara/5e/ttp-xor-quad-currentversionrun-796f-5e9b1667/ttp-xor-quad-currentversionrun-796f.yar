rule TTP_XOR_QUAD_CurrentVersionRun_796f {
  strings:
    $key_796f = { 2a 00 [2] 0e 0e [2] 25 22 [2] 0b 00 [2] 1f 1b [2] 10 01 [2] 0e 1c [2] 0c 1d [2] 17 1b [2] 0b 1c [2] 17 33 }

  condition:
    any of them
}