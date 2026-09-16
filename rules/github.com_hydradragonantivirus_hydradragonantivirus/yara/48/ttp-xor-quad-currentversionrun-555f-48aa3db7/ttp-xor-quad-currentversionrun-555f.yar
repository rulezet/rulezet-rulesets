rule TTP_XOR_QUAD_CurrentVersionRun_555f {
  strings:
    $key_555f = { 06 30 [2] 22 3e [2] 09 12 [2] 27 30 [2] 33 2b [2] 3c 31 [2] 22 2c [2] 20 2d [2] 3b 2b [2] 27 2c [2] 3b 03 }

  condition:
    any of them
}