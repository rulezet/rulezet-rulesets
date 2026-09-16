rule TTP_XOR_QUAD_CurrentVersionRun_7140 {
  strings:
    $key_7140 = { 22 2f [2] 06 21 [2] 2d 0d [2] 03 2f [2] 17 34 [2] 18 2e [2] 06 33 [2] 04 32 [2] 1f 34 [2] 03 33 [2] 1f 1c }

  condition:
    any of them
}