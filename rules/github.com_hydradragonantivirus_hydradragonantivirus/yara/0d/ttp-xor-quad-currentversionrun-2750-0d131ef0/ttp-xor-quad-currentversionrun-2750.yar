rule TTP_XOR_QUAD_CurrentVersionRun_2750 {
  strings:
    $key_2750 = { 74 3f [2] 50 31 [2] 7b 1d [2] 55 3f [2] 41 24 [2] 4e 3e [2] 50 23 [2] 52 22 [2] 49 24 [2] 55 23 [2] 49 0c }

  condition:
    any of them
}