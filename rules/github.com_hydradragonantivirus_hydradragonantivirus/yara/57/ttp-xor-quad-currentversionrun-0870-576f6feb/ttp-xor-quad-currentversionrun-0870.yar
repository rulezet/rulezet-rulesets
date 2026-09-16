rule TTP_XOR_QUAD_CurrentVersionRun_0870 {
  strings:
    $key_0870 = { 5b 1f [2] 7f 11 [2] 54 3d [2] 7a 1f [2] 6e 04 [2] 61 1e [2] 7f 03 [2] 7d 02 [2] 66 04 [2] 7a 03 [2] 66 2c }

  condition:
    any of them
}