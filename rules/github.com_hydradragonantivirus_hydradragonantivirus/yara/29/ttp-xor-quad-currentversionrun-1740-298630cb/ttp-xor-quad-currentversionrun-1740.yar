rule TTP_XOR_QUAD_CurrentVersionRun_1740 {
  strings:
    $key_1740 = { 44 2f [2] 60 21 [2] 4b 0d [2] 65 2f [2] 71 34 [2] 7e 2e [2] 60 33 [2] 62 32 [2] 79 34 [2] 65 33 [2] 79 1c }

  condition:
    any of them
}