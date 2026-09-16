rule TTP_XOR_QUAD_CurrentVersionRun_2440 {
  strings:
    $key_2440 = { 77 2f [2] 53 21 [2] 78 0d [2] 56 2f [2] 42 34 [2] 4d 2e [2] 53 33 [2] 51 32 [2] 4a 34 [2] 56 33 [2] 4a 1c }

  condition:
    any of them
}