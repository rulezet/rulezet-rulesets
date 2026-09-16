rule TTP_XOR_QUAD_CurrentVersionRun_6770 {
  strings:
    $key_6770 = { 34 1f [2] 10 11 [2] 3b 3d [2] 15 1f [2] 01 04 [2] 0e 1e [2] 10 03 [2] 12 02 [2] 09 04 [2] 15 03 [2] 09 2c }

  condition:
    any of them
}