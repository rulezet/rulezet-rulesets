rule TTP_XOR_QUAD_CurrentVersionRun_4630 {
  strings:
    $key_4630 = { 15 5f [2] 31 51 [2] 1a 7d [2] 34 5f [2] 20 44 [2] 2f 5e [2] 31 43 [2] 33 42 [2] 28 44 [2] 34 43 [2] 28 6c }

  condition:
    any of them
}