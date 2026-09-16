rule TTP_XOR_QUAD_CurrentVersionRun_685f {
  strings:
    $key_685f = { 3b 30 [2] 1f 3e [2] 34 12 [2] 1a 30 [2] 0e 2b [2] 01 31 [2] 1f 2c [2] 1d 2d [2] 06 2b [2] 1a 2c [2] 06 03 }

  condition:
    any of them
}