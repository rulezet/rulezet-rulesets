rule TTP_XOR_QUAD_CurrentVersionRun_6740 {
  strings:
    $key_6740 = { 34 2f [2] 10 21 [2] 3b 0d [2] 15 2f [2] 01 34 [2] 0e 2e [2] 10 33 [2] 12 32 [2] 09 34 [2] 15 33 [2] 09 1c }

  condition:
    any of them
}