rule TTP_XOR_QUAD_CurrentVersionRun_e361 {
  strings:
    $key_e361 = { b0 0e [2] 94 00 [2] bf 2c [2] 91 0e [2] 85 15 [2] 8a 0f [2] 94 12 [2] 96 13 [2] 8d 15 [2] 91 12 [2] 8d 3d }

  condition:
    any of them
}