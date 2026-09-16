rule TTP_XOR_QUAD_CurrentVersionRun_ef61 {
  strings:
    $key_ef61 = { bc 0e [2] 98 00 [2] b3 2c [2] 9d 0e [2] 89 15 [2] 86 0f [2] 98 12 [2] 9a 13 [2] 81 15 [2] 9d 12 [2] 81 3d }

  condition:
    any of them
}