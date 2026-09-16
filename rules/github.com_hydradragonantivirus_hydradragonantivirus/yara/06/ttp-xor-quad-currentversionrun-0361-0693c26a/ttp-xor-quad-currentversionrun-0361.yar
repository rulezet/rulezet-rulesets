rule TTP_XOR_QUAD_CurrentVersionRun_0361 {
  strings:
    $key_0361 = { 50 0e [2] 74 00 [2] 5f 2c [2] 71 0e [2] 65 15 [2] 6a 0f [2] 74 12 [2] 76 13 [2] 6d 15 [2] 71 12 [2] 6d 3d }

  condition:
    any of them
}