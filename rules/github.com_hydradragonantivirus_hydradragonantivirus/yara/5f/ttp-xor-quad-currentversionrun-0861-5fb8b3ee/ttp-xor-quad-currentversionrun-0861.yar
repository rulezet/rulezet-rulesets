rule TTP_XOR_QUAD_CurrentVersionRun_0861 {
  strings:
    $key_0861 = { 5b 0e [2] 7f 00 [2] 54 2c [2] 7a 0e [2] 6e 15 [2] 61 0f [2] 7f 12 [2] 7d 13 [2] 66 15 [2] 7a 12 [2] 66 3d }

  condition:
    any of them
}