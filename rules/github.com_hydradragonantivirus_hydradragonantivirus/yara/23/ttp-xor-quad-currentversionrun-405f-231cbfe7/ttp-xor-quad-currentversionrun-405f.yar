rule TTP_XOR_QUAD_CurrentVersionRun_405f {
  strings:
    $key_405f = { 13 30 [2] 37 3e [2] 1c 12 [2] 32 30 [2] 26 2b [2] 29 31 [2] 37 2c [2] 35 2d [2] 2e 2b [2] 32 2c [2] 2e 03 }

  condition:
    any of them
}