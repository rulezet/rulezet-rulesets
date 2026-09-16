rule TTP_XOR_QUAD_CurrentVersionRun_ce42 {
  strings:
    $key_ce42 = { 9d 2d [2] b9 23 [2] 92 0f [2] bc 2d [2] a8 36 [2] a7 2c [2] b9 31 [2] bb 30 [2] a0 36 [2] bc 31 [2] a0 1e }

  condition:
    any of them
}