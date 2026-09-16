rule TTP_XOR_QUAD_CurrentVersionRun_0542 {
  strings:
    $key_0542 = { 56 2d [2] 72 23 [2] 59 0f [2] 77 2d [2] 63 36 [2] 6c 2c [2] 72 31 [2] 70 30 [2] 6b 36 [2] 77 31 [2] 6b 1e }

  condition:
    any of them
}