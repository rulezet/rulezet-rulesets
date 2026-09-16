rule TTP_XOR_QUAD_CurrentVersionRun_755f {
  strings:
    $key_755f = { 26 30 [2] 02 3e [2] 29 12 [2] 07 30 [2] 13 2b [2] 1c 31 [2] 02 2c [2] 00 2d [2] 1b 2b [2] 07 2c [2] 1b 03 }

  condition:
    any of them
}