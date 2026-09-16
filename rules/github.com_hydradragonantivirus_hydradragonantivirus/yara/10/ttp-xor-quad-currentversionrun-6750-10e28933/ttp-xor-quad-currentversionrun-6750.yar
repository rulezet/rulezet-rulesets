rule TTP_XOR_QUAD_CurrentVersionRun_6750 {
  strings:
    $key_6750 = { 34 3f [2] 10 31 [2] 3b 1d [2] 15 3f [2] 01 24 [2] 0e 3e [2] 10 23 [2] 12 22 [2] 09 24 [2] 15 23 [2] 09 0c }

  condition:
    any of them
}