rule TTP_XOR_QUAD_CurrentVersionRun_e342 {
  strings:
    $key_e342 = { b0 2d [2] 94 23 [2] bf 0f [2] 91 2d [2] 85 36 [2] 8a 2c [2] 94 31 [2] 96 30 [2] 8d 36 [2] 91 31 [2] 8d 1e }

  condition:
    any of them
}