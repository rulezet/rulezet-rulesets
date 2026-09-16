rule TTP_XOR_QUAD_CurrentVersionRun_e770 {
  strings:
    $key_e770 = { b4 1f [2] 90 11 [2] bb 3d [2] 95 1f [2] 81 04 [2] 8e 1e [2] 90 03 [2] 92 02 [2] 89 04 [2] 95 03 [2] 89 2c }

  condition:
    any of them
}