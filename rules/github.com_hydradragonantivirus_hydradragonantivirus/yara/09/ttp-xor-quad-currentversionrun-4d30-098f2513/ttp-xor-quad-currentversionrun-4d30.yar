rule TTP_XOR_QUAD_CurrentVersionRun_4d30 {
  strings:
    $key_4d30 = { 1e 5f [2] 3a 51 [2] 11 7d [2] 3f 5f [2] 2b 44 [2] 24 5e [2] 3a 43 [2] 38 42 [2] 23 44 [2] 3f 43 [2] 23 6c }

  condition:
    any of them
}