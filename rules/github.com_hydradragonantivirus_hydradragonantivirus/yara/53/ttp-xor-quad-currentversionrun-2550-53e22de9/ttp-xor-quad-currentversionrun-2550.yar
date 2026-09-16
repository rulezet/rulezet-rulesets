rule TTP_XOR_QUAD_CurrentVersionRun_2550 {
  strings:
    $key_2550 = { 76 3f [2] 52 31 [2] 79 1d [2] 57 3f [2] 43 24 [2] 4c 3e [2] 52 23 [2] 50 22 [2] 4b 24 [2] 57 23 [2] 4b 0c }

  condition:
    any of them
}