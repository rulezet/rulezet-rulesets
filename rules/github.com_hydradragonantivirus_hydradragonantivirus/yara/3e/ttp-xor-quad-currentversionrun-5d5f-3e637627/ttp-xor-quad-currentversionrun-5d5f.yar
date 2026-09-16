rule TTP_XOR_QUAD_CurrentVersionRun_5d5f {
  strings:
    $key_5d5f = { 0e 30 [2] 2a 3e [2] 01 12 [2] 2f 30 [2] 3b 2b [2] 34 31 [2] 2a 2c [2] 28 2d [2] 33 2b [2] 2f 2c [2] 33 03 }

  condition:
    any of them
}