rule TTP_XOR_QUAD_CurrentVersionRun_3070 {
  strings:
    $key_3070 = { 63 1f [2] 47 11 [2] 6c 3d [2] 42 1f [2] 56 04 [2] 59 1e [2] 47 03 [2] 45 02 [2] 5e 04 [2] 42 03 [2] 5e 2c }

  condition:
    any of them
}