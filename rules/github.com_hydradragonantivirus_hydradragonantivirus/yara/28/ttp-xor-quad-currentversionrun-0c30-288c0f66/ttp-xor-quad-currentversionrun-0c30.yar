rule TTP_XOR_QUAD_CurrentVersionRun_0c30 {
  strings:
    $key_0c30 = { 5f 5f [2] 7b 51 [2] 50 7d [2] 7e 5f [2] 6a 44 [2] 65 5e [2] 7b 43 [2] 79 42 [2] 62 44 [2] 7e 43 [2] 62 6c }

  condition:
    any of them
}