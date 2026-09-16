rule TTP_XOR_QUAD_CurrentVersionRun_465f {
  strings:
    $key_465f = { 15 30 [2] 31 3e [2] 1a 12 [2] 34 30 [2] 20 2b [2] 2f 31 [2] 31 2c [2] 33 2d [2] 28 2b [2] 34 2c [2] 28 03 }

  condition:
    any of them
}