rule TTP_XOR_QUAD_CurrentVersionRun_e75f {
  strings:
    $key_e75f = { b4 30 [2] 90 3e [2] bb 12 [2] 95 30 [2] 81 2b [2] 8e 31 [2] 90 2c [2] 92 2d [2] 89 2b [2] 95 2c [2] 89 03 }

  condition:
    any of them
}