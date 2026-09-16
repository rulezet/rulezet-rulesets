rule TTP_XOR_QUAD_CurrentVersionRun_f361 {
  strings:
    $key_f361 = { a0 0e [2] 84 00 [2] af 2c [2] 81 0e [2] 95 15 [2] 9a 0f [2] 84 12 [2] 86 13 [2] 9d 15 [2] 81 12 [2] 9d 3d }

  condition:
    any of them
}