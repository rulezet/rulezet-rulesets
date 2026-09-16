rule TTP_XOR_QUAD_CurrentVersionRun_1840 {
  strings:
    $key_1840 = { 4b 2f [2] 6f 21 [2] 44 0d [2] 6a 2f [2] 7e 34 [2] 71 2e [2] 6f 33 [2] 6d 32 [2] 76 34 [2] 6a 33 [2] 76 1c }

  condition:
    any of them
}