rule TTP_XOR_QUAD_CurrentVersionRun_1770 {
  strings:
    $key_1770 = { 44 1f [2] 60 11 [2] 4b 3d [2] 65 1f [2] 71 04 [2] 7e 1e [2] 60 03 [2] 62 02 [2] 79 04 [2] 65 03 [2] 79 2c }

  condition:
    any of them
}