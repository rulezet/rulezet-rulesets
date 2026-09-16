rule TTP_XOR_QUAD_CurrentVersionRun_3640 {
  strings:
    $key_3640 = { 65 2f [2] 41 21 [2] 6a 0d [2] 44 2f [2] 50 34 [2] 5f 2e [2] 41 33 [2] 43 32 [2] 58 34 [2] 44 33 [2] 58 1c }

  condition:
    any of them
}