rule TTP_XOR_QUAD_CurrentVersionRun_425f {
  strings:
    $key_425f = { 11 30 [2] 35 3e [2] 1e 12 [2] 30 30 [2] 24 2b [2] 2b 31 [2] 35 2c [2] 37 2d [2] 2c 2b [2] 30 2c [2] 2c 03 }

  condition:
    any of them
}