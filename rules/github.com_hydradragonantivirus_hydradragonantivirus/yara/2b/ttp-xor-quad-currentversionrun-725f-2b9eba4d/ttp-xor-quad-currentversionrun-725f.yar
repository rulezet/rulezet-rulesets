rule TTP_XOR_QUAD_CurrentVersionRun_725f {
  strings:
    $key_725f = { 21 30 [2] 05 3e [2] 2e 12 [2] 00 30 [2] 14 2b [2] 1b 31 [2] 05 2c [2] 07 2d [2] 1c 2b [2] 00 2c [2] 1c 03 }

  condition:
    any of them
}