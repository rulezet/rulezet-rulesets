rule TTP_XOR_QUAD_CurrentVersionRun_e76f {
  strings:
    $key_e76f = { b4 00 [2] 90 0e [2] bb 22 [2] 95 00 [2] 81 1b [2] 8e 01 [2] 90 1c [2] 92 1d [2] 89 1b [2] 95 1c [2] 89 33 }

  condition:
    any of them
}