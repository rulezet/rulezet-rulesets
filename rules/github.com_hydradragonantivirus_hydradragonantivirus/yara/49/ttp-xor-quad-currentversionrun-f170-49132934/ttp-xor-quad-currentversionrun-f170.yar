rule TTP_XOR_QUAD_CurrentVersionRun_f170 {
  strings:
    $key_f170 = { a2 1f [2] 86 11 [2] ad 3d [2] 83 1f [2] 97 04 [2] 98 1e [2] 86 03 [2] 84 02 [2] 9f 04 [2] 83 03 [2] 9f 2c }

  condition:
    any of them
}