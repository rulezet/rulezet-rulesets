rule TTP_XOR_QUAD_CurrentVersionRun_4440 {
  strings:
    $key_4440 = { 17 2f [2] 33 21 [2] 18 0d [2] 36 2f [2] 22 34 [2] 2d 2e [2] 33 33 [2] 31 32 [2] 2a 34 [2] 36 33 [2] 2a 1c }

  condition:
    any of them
}