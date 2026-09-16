rule TTP_XOR_QUAD_CurrentVersionRun_7c30 {
  strings:
    $key_7c30 = { 2f 5f [2] 0b 51 [2] 20 7d [2] 0e 5f [2] 1a 44 [2] 15 5e [2] 0b 43 [2] 09 42 [2] 12 44 [2] 0e 43 [2] 12 6c }

  condition:
    any of them
}