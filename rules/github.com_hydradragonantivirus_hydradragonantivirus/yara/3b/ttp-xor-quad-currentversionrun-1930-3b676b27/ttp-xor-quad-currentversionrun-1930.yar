rule TTP_XOR_QUAD_CurrentVersionRun_1930 {
  strings:
    $key_1930 = { 4a 5f [2] 6e 51 [2] 45 7d [2] 6b 5f [2] 7f 44 [2] 70 5e [2] 6e 43 [2] 6c 42 [2] 77 44 [2] 6b 43 [2] 77 6c }

  condition:
    any of them
}