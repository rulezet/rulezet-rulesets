rule TTP_XOR_QUAD_CurrentVersionRun_0543 {
  strings:
    $key_0543 = { 56 2c [2] 72 22 [2] 59 0e [2] 77 2c [2] 63 37 [2] 6c 2d [2] 72 30 [2] 70 31 [2] 6b 37 [2] 77 30 [2] 6b 1f }

  condition:
    any of them
}