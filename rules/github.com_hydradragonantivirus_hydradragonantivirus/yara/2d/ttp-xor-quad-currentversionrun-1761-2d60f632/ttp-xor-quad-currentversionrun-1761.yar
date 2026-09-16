rule TTP_XOR_QUAD_CurrentVersionRun_1761 {
  strings:
    $key_1761 = { 44 0e [2] 60 00 [2] 4b 2c [2] 65 0e [2] 71 15 [2] 7e 0f [2] 60 12 [2] 62 13 [2] 79 15 [2] 65 12 [2] 79 3d }

  condition:
    any of them
}