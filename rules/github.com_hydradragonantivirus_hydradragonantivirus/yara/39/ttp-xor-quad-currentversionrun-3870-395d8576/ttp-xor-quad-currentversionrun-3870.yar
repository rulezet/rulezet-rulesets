rule TTP_XOR_QUAD_CurrentVersionRun_3870 {
  strings:
    $key_3870 = { 6b 1f [2] 4f 11 [2] 64 3d [2] 4a 1f [2] 5e 04 [2] 51 1e [2] 4f 03 [2] 4d 02 [2] 56 04 [2] 4a 03 [2] 56 2c }

  condition:
    any of them
}