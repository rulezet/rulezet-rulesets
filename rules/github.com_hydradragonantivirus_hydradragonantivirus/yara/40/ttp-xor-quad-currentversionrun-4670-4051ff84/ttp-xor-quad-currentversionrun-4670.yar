rule TTP_XOR_QUAD_CurrentVersionRun_4670 {
  strings:
    $key_4670 = { 15 1f [2] 31 11 [2] 1a 3d [2] 34 1f [2] 20 04 [2] 2f 1e [2] 31 03 [2] 33 02 [2] 28 04 [2] 34 03 [2] 28 2c }

  condition:
    any of them
}