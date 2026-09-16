rule TTP_XOR_QUAD_CurrentVersionRun_7b5f {
  strings:
    $key_7b5f = { 28 30 [2] 0c 3e [2] 27 12 [2] 09 30 [2] 1d 2b [2] 12 31 [2] 0c 2c [2] 0e 2d [2] 15 2b [2] 09 2c [2] 15 03 }

  condition:
    any of them
}