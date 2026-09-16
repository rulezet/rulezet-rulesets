rule TTP_XOR_QUAD_CurrentVersionRun_3630 {
  strings:
    $key_3630 = { 65 5f [2] 41 51 [2] 6a 7d [2] 44 5f [2] 50 44 [2] 5f 5e [2] 41 43 [2] 43 42 [2] 58 44 [2] 44 43 [2] 58 6c }

  condition:
    any of them
}