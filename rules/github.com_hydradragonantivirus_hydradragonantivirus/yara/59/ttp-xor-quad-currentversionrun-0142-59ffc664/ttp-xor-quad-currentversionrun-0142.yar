rule TTP_XOR_QUAD_CurrentVersionRun_0142 {
  strings:
    $key_0142 = { 52 2d [2] 76 23 [2] 5d 0f [2] 73 2d [2] 67 36 [2] 68 2c [2] 76 31 [2] 74 30 [2] 6f 36 [2] 73 31 [2] 6f 1e }

  condition:
    any of them
}