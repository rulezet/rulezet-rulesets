rule TTP_XOR_QUAD_CurrentVersionRun_605f {
  strings:
    $key_605f = { 33 30 [2] 17 3e [2] 3c 12 [2] 12 30 [2] 06 2b [2] 09 31 [2] 17 2c [2] 15 2d [2] 0e 2b [2] 12 2c [2] 0e 03 }

  condition:
    any of them
}