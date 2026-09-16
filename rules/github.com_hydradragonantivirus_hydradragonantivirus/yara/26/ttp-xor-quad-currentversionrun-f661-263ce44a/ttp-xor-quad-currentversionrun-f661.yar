rule TTP_XOR_QUAD_CurrentVersionRun_f661 {
  strings:
    $key_f661 = { a5 0e [2] 81 00 [2] aa 2c [2] 84 0e [2] 90 15 [2] 9f 0f [2] 81 12 [2] 83 13 [2] 98 15 [2] 84 12 [2] 98 3d }

  condition:
    any of them
}