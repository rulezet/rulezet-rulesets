rule TTP_XOR_QUAD_CurrentVersionRun_7c5f {
  strings:
    $key_7c5f = { 2f 30 [2] 0b 3e [2] 20 12 [2] 0e 30 [2] 1a 2b [2] 15 31 [2] 0b 2c [2] 09 2d [2] 12 2b [2] 0e 2c [2] 12 03 }

  condition:
    any of them
}