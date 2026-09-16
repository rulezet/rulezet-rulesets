rule TTP_XOR_QUAD_CurrentVersionRun_7930 {
  strings:
    $key_7930 = { 2a 5f [2] 0e 51 [2] 25 7d [2] 0b 5f [2] 1f 44 [2] 10 5e [2] 0e 43 [2] 0c 42 [2] 17 44 [2] 0b 43 [2] 17 6c }

  condition:
    any of them
}