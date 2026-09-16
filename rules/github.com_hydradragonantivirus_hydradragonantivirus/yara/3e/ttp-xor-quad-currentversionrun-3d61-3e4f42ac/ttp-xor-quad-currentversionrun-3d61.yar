rule TTP_XOR_QUAD_CurrentVersionRun_3d61 {
  strings:
    $key_3d61 = { 6e 0e [2] 4a 00 [2] 61 2c [2] 4f 0e [2] 5b 15 [2] 54 0f [2] 4a 12 [2] 48 13 [2] 53 15 [2] 4f 12 [2] 53 3d }

  condition:
    any of them
}