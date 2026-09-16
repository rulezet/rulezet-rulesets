rule TTP_XOR_QUAD_CurrentVersionRun_f270 {
  strings:
    $key_f270 = { a1 1f [2] 85 11 [2] ae 3d [2] 80 1f [2] 94 04 [2] 9b 1e [2] 85 03 [2] 87 02 [2] 9c 04 [2] 80 03 [2] 9c 2c }

  condition:
    any of them
}