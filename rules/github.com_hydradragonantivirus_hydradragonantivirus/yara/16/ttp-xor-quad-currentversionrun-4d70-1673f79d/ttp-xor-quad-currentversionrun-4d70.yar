rule TTP_XOR_QUAD_CurrentVersionRun_4d70 {
  strings:
    $key_4d70 = { 1e 1f [2] 3a 11 [2] 11 3d [2] 3f 1f [2] 2b 04 [2] 24 1e [2] 3a 03 [2] 38 02 [2] 23 04 [2] 3f 03 [2] 23 2c }

  condition:
    any of them
}