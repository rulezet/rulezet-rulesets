rule TTP_XOR_QUAD_CurrentVersionRun_6730 {
  strings:
    $key_6730 = { 34 5f [2] 10 51 [2] 3b 7d [2] 15 5f [2] 01 44 [2] 0e 5e [2] 10 43 [2] 12 42 [2] 09 44 [2] 15 43 [2] 09 6c }

  condition:
    any of them
}