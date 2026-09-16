rule TTP_XOR_QUAD_CurrentVersionRun_1530 {
  strings:
    $key_1530 = { 46 5f [2] 62 51 [2] 49 7d [2] 67 5f [2] 73 44 [2] 7c 5e [2] 62 43 [2] 60 42 [2] 7b 44 [2] 67 43 [2] 7b 6c }

  condition:
    any of them
}