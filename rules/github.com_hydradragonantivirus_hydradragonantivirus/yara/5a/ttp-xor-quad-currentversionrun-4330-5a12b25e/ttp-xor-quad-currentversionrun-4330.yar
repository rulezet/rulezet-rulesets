rule TTP_XOR_QUAD_CurrentVersionRun_4330 {
  strings:
    $key_4330 = { 10 5f [2] 34 51 [2] 1f 7d [2] 31 5f [2] 25 44 [2] 2a 5e [2] 34 43 [2] 36 42 [2] 2d 44 [2] 31 43 [2] 2d 6c }

  condition:
    any of them
}