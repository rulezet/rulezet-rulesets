rule TTP_XOR_QUAD_CurrentVersionRun_7d61 {
  strings:
    $key_7d61 = { 2e 0e [2] 0a 00 [2] 21 2c [2] 0f 0e [2] 1b 15 [2] 14 0f [2] 0a 12 [2] 08 13 [2] 13 15 [2] 0f 12 [2] 13 3d }

  condition:
    any of them
}