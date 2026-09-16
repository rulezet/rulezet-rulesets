rule TTP_XOR_QUAD_CurrentVersionRun_2d61 {
  strings:
    $key_2d61 = { 7e 0e [2] 5a 00 [2] 71 2c [2] 5f 0e [2] 4b 15 [2] 44 0f [2] 5a 12 [2] 58 13 [2] 43 15 [2] 5f 12 [2] 43 3d }

  condition:
    any of them
}