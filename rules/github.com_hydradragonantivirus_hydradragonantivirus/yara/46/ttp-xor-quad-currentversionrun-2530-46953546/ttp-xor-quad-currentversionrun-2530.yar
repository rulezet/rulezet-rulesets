rule TTP_XOR_QUAD_CurrentVersionRun_2530 {
  strings:
    $key_2530 = { 76 5f [2] 52 51 [2] 79 7d [2] 57 5f [2] 43 44 [2] 4c 5e [2] 52 43 [2] 50 42 [2] 4b 44 [2] 57 43 [2] 4b 6c }

  condition:
    any of them
}