rule TTP_XOR_QUAD_CurrentVersionRun_2661 {
  strings:
    $key_2661 = { 75 0e [2] 51 00 [2] 7a 2c [2] 54 0e [2] 40 15 [2] 4f 0f [2] 51 12 [2] 53 13 [2] 48 15 [2] 54 12 [2] 48 3d }

  condition:
    any of them
}