rule TTP_XOR_QUAD_CurrentVersionRun_e261 {
  strings:
    $key_e261 = { b1 0e [2] 95 00 [2] be 2c [2] 90 0e [2] 84 15 [2] 8b 0f [2] 95 12 [2] 97 13 [2] 8c 15 [2] 90 12 [2] 8c 3d }

  condition:
    any of them
}