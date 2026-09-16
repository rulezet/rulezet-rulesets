rule TTP_XOR_QUAD_CurrentVersionRun_5d30 {
  strings:
    $key_5d30 = { 0e 5f [2] 2a 51 [2] 01 7d [2] 2f 5f [2] 3b 44 [2] 34 5e [2] 2a 43 [2] 28 42 [2] 33 44 [2] 2f 43 [2] 33 6c }

  condition:
    any of them
}