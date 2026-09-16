rule TTP_XOR_QUAD_CurrentVersionRun_f643 {
  strings:
    $key_f643 = { a5 2c [2] 81 22 [2] aa 0e [2] 84 2c [2] 90 37 [2] 9f 2d [2] 81 30 [2] 83 31 [2] 98 37 [2] 84 30 [2] 98 1f }

  condition:
    any of them
}