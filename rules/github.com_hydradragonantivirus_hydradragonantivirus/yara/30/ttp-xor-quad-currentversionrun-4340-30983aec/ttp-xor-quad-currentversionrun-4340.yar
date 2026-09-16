rule TTP_XOR_QUAD_CurrentVersionRun_4340 {
  strings:
    $key_4340 = { 10 2f [2] 34 21 [2] 1f 0d [2] 31 2f [2] 25 34 [2] 2a 2e [2] 34 33 [2] 36 32 [2] 2d 34 [2] 31 33 [2] 2d 1c }

  condition:
    any of them
}