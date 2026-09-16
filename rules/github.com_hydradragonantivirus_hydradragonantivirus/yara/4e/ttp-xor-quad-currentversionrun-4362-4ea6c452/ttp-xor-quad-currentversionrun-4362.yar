rule TTP_XOR_QUAD_CurrentVersionRun_4362 {
  strings:
    $key_4362 = { 10 0d [2] 34 03 [2] 1f 2f [2] 31 0d [2] 25 16 [2] 2a 0c [2] 34 11 [2] 36 10 [2] 2d 16 [2] 31 11 [2] 2d 3e }

  condition:
    any of them
}