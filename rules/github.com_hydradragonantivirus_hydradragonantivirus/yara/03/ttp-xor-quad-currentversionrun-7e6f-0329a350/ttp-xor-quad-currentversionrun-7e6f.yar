rule TTP_XOR_QUAD_CurrentVersionRun_7e6f {
  strings:
    $key_7e6f = { 2d 00 [2] 09 0e [2] 22 22 [2] 0c 00 [2] 18 1b [2] 17 01 [2] 09 1c [2] 0b 1d [2] 10 1b [2] 0c 1c [2] 10 33 }

  condition:
    any of them
}