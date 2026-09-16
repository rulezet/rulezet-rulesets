rule TTP_XOR_QUAD_CurrentVersionRun_e730 {
  strings:
    $key_e730 = { b4 5f [2] 90 51 [2] bb 7d [2] 95 5f [2] 81 44 [2] 8e 5e [2] 90 43 [2] 92 42 [2] 89 44 [2] 95 43 [2] 89 6c }

  condition:
    any of them
}