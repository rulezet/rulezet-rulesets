rule TTP_XOR_QUAD_CurrentVersionRun_0070 {
  strings:
    $key_0070 = { 53 1f [2] 77 11 [2] 5c 3d [2] 72 1f [2] 66 04 [2] 69 1e [2] 77 03 [2] 75 02 [2] 6e 04 [2] 72 03 [2] 6e 2c }

  condition:
    any of them
}