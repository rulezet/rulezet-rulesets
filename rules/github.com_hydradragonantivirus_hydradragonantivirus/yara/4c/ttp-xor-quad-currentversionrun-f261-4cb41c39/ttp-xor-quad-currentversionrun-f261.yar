rule TTP_XOR_QUAD_CurrentVersionRun_f261 {
  strings:
    $key_f261 = { a1 0e [2] 85 00 [2] ae 2c [2] 80 0e [2] 94 15 [2] 9b 0f [2] 85 12 [2] 87 13 [2] 9c 15 [2] 80 12 [2] 9c 3d }

  condition:
    any of them
}