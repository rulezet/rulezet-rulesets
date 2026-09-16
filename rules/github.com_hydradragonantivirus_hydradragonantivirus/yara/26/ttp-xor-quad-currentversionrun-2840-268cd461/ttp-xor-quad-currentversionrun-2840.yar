rule TTP_XOR_QUAD_CurrentVersionRun_2840 {
  strings:
    $key_2840 = { 7b 2f [2] 5f 21 [2] 74 0d [2] 5a 2f [2] 4e 34 [2] 41 2e [2] 5f 33 [2] 5d 32 [2] 46 34 [2] 5a 33 [2] 46 1c }

  condition:
    any of them
}