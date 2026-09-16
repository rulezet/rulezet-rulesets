rule TTP_XOR_QUAD_CurrentVersionRun_5a5f {
  strings:
    $key_5a5f = { 09 30 [2] 2d 3e [2] 06 12 [2] 28 30 [2] 3c 2b [2] 33 31 [2] 2d 2c [2] 2f 2d [2] 34 2b [2] 28 2c [2] 34 03 }

  condition:
    any of them
}