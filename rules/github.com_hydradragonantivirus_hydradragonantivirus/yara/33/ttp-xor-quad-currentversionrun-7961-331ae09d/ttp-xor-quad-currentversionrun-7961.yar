rule TTP_XOR_QUAD_CurrentVersionRun_7961 {
  strings:
    $key_7961 = { 2a 0e [2] 0e 00 [2] 25 2c [2] 0b 0e [2] 1f 15 [2] 10 0f [2] 0e 12 [2] 0c 13 [2] 17 15 [2] 0b 12 [2] 17 3d }

  condition:
    any of them
}