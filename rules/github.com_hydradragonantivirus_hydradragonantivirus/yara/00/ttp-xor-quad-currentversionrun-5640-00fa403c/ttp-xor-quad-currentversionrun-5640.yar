rule TTP_XOR_QUAD_CurrentVersionRun_5640 {
  strings:
    $key_5640 = { 05 2f [2] 21 21 [2] 0a 0d [2] 24 2f [2] 30 34 [2] 3f 2e [2] 21 33 [2] 23 32 [2] 38 34 [2] 24 33 [2] 38 1c }

  condition:
    any of them
}