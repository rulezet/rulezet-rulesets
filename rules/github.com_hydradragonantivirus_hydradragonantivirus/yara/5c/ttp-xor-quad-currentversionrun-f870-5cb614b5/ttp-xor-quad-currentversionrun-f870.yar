rule TTP_XOR_QUAD_CurrentVersionRun_f870 {
  strings:
    $key_f870 = { ab 1f [2] 8f 11 [2] a4 3d [2] 8a 1f [2] 9e 04 [2] 91 1e [2] 8f 03 [2] 8d 02 [2] 96 04 [2] 8a 03 [2] 96 2c }

  condition:
    any of them
}