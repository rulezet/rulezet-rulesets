rule TTP_XOR_QUAD_CurrentVersionRun_ef70 {
  strings:
    $key_ef70 = { bc 1f [2] 98 11 [2] b3 3d [2] 9d 1f [2] 89 04 [2] 86 1e [2] 98 03 [2] 9a 02 [2] 81 04 [2] 9d 03 [2] 81 2c }

  condition:
    any of them
}