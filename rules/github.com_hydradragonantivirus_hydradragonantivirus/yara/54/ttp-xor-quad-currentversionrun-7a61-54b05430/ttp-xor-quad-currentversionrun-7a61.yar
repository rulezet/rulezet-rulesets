rule TTP_XOR_QUAD_CurrentVersionRun_7a61 {
  strings:
    $key_7a61 = { 29 0e [2] 0d 00 [2] 26 2c [2] 08 0e [2] 1c 15 [2] 13 0f [2] 0d 12 [2] 0f 13 [2] 14 15 [2] 08 12 [2] 14 3d }

  condition:
    any of them
}