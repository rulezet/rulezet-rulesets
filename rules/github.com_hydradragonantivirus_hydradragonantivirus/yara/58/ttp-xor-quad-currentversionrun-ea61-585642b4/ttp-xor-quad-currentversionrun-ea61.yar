rule TTP_XOR_QUAD_CurrentVersionRun_ea61 {
  strings:
    $key_ea61 = { b9 0e [2] 9d 00 [2] b6 2c [2] 98 0e [2] 8c 15 [2] 83 0f [2] 9d 12 [2] 9f 13 [2] 84 15 [2] 98 12 [2] 84 3d }

  condition:
    any of them
}