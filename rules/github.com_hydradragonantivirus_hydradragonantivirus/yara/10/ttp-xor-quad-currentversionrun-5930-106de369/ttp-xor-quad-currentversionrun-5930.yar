rule TTP_XOR_QUAD_CurrentVersionRun_5930 {
  strings:
    $key_5930 = { 0a 5f [2] 2e 51 [2] 05 7d [2] 2b 5f [2] 3f 44 [2] 30 5e [2] 2e 43 [2] 2c 42 [2] 37 44 [2] 2b 43 [2] 37 6c }

  condition:
    any of them
}