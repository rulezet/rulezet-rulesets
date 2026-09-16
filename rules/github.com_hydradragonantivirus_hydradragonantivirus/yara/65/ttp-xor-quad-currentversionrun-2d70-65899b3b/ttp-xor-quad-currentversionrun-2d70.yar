rule TTP_XOR_QUAD_CurrentVersionRun_2d70 {
  strings:
    $key_2d70 = { 7e 1f [2] 5a 11 [2] 71 3d [2] 5f 1f [2] 4b 04 [2] 44 1e [2] 5a 03 [2] 58 02 [2] 43 04 [2] 5f 03 [2] 43 2c }

  condition:
    any of them
}