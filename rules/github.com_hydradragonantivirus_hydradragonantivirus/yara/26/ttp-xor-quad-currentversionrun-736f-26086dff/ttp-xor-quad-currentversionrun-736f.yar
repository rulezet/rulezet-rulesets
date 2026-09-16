rule TTP_XOR_QUAD_CurrentVersionRun_736f {
  strings:
    $key_736f = { 20 00 [2] 04 0e [2] 2f 22 [2] 01 00 [2] 15 1b [2] 1a 01 [2] 04 1c [2] 06 1d [2] 1d 1b [2] 01 1c [2] 1d 33 }

  condition:
    any of them
}