rule TTP_XOR_QUAD_CurrentVersionRun_e74d {
  strings:
    $key_e74d = { b4 22 [2] 90 2c [2] bb 00 [2] 95 22 [2] 81 39 [2] 8e 23 [2] 90 3e [2] 92 3f [2] 89 39 [2] 95 3e [2] 89 11 }

  condition:
    any of them
}