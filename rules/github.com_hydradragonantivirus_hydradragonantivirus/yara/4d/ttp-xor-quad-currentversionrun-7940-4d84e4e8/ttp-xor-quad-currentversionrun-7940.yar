rule TTP_XOR_QUAD_CurrentVersionRun_7940 {
  strings:
    $key_7940 = { 2a 2f [2] 0e 21 [2] 25 0d [2] 0b 2f [2] 1f 34 [2] 10 2e [2] 0e 33 [2] 0c 32 [2] 17 34 [2] 0b 33 [2] 17 1c }

  condition:
    any of them
}