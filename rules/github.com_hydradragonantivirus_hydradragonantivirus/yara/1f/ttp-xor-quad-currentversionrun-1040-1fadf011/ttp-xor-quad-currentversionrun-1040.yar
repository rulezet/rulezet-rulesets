rule TTP_XOR_QUAD_CurrentVersionRun_1040 {
  strings:
    $key_1040 = { 43 2f [2] 67 21 [2] 4c 0d [2] 62 2f [2] 76 34 [2] 79 2e [2] 67 33 [2] 65 32 [2] 7e 34 [2] 62 33 [2] 7e 1c }

  condition:
    any of them
}