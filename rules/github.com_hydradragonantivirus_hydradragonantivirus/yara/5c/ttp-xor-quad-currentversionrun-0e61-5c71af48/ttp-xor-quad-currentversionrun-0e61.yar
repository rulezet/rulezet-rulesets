rule TTP_XOR_QUAD_CurrentVersionRun_0e61 {
  strings:
    $key_0e61 = { 5d 0e [2] 79 00 [2] 52 2c [2] 7c 0e [2] 68 15 [2] 67 0f [2] 79 12 [2] 7b 13 [2] 60 15 [2] 7c 12 [2] 60 3d }

  condition:
    any of them
}