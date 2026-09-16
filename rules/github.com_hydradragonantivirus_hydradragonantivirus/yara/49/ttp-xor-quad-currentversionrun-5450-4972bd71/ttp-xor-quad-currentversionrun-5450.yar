rule TTP_XOR_QUAD_CurrentVersionRun_5450 {
  strings:
    $key_5450 = { 07 3f [2] 23 31 [2] 08 1d [2] 26 3f [2] 32 24 [2] 3d 3e [2] 23 23 [2] 21 22 [2] 3a 24 [2] 26 23 [2] 3a 0c }

  condition:
    any of them
}