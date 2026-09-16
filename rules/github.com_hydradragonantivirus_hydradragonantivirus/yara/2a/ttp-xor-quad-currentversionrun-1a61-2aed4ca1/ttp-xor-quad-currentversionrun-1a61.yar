rule TTP_XOR_QUAD_CurrentVersionRun_1a61 {
  strings:
    $key_1a61 = { 49 0e [2] 6d 00 [2] 46 2c [2] 68 0e [2] 7c 15 [2] 73 0f [2] 6d 12 [2] 6f 13 [2] 74 15 [2] 68 12 [2] 74 3d }

  condition:
    any of them
}