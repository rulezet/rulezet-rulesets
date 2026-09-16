rule TTP_XOR_QUAD_CurrentVersionRun_f770 {
  strings:
    $key_f770 = { a4 1f [2] 80 11 [2] ab 3d [2] 85 1f [2] 91 04 [2] 9e 1e [2] 80 03 [2] 82 02 [2] 99 04 [2] 85 03 [2] 99 2c }

  condition:
    any of them
}