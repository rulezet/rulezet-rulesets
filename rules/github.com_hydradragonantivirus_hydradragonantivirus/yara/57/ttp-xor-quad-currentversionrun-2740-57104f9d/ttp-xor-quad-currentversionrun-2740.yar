rule TTP_XOR_QUAD_CurrentVersionRun_2740 {
  strings:
    $key_2740 = { 74 2f [2] 50 21 [2] 7b 0d [2] 55 2f [2] 41 34 [2] 4e 2e [2] 50 33 [2] 52 32 [2] 49 34 [2] 55 33 [2] 49 1c }

  condition:
    any of them
}