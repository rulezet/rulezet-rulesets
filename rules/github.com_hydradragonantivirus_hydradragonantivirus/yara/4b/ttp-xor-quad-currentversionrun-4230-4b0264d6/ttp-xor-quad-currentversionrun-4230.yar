rule TTP_XOR_QUAD_CurrentVersionRun_4230 {
  strings:
    $key_4230 = { 11 5f [2] 35 51 [2] 1e 7d [2] 30 5f [2] 24 44 [2] 2b 5e [2] 35 43 [2] 37 42 [2] 2c 44 [2] 30 43 [2] 2c 6c }

  condition:
    any of them
}