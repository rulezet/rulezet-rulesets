rule TTP_XOR_QUAD_CurrentVersionRun_5d61 {
  strings:
    $key_5d61 = { 0e 0e [2] 2a 00 [2] 01 2c [2] 2f 0e [2] 3b 15 [2] 34 0f [2] 2a 12 [2] 28 13 [2] 33 15 [2] 2f 12 [2] 33 3d }

  condition:
    any of them
}