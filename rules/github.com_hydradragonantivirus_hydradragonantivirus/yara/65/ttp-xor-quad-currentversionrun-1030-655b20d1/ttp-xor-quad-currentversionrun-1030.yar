rule TTP_XOR_QUAD_CurrentVersionRun_1030 {
  strings:
    $key_1030 = { 43 5f [2] 67 51 [2] 4c 7d [2] 62 5f [2] 76 44 [2] 79 5e [2] 67 43 [2] 65 42 [2] 7e 44 [2] 62 43 [2] 7e 6c }

  condition:
    any of them
}