rule TTP_XOR_QUAD_CurrentVersionRun_f370 {
  strings:
    $key_f370 = { a0 1f [2] 84 11 [2] af 3d [2] 81 1f [2] 95 04 [2] 9a 1e [2] 84 03 [2] 86 02 [2] 9d 04 [2] 81 03 [2] 9d 2c }

  condition:
    any of them
}