rule TTP_XOR_QUAD_CurrentVersionRun_7c22 {
  strings:
    $key_7c22 = { 2f 4d [2] 0b 43 [2] 20 6f [2] 0e 4d [2] 1a 56 [2] 15 4c [2] 0b 51 [2] 09 50 [2] 12 56 [2] 0e 51 [2] 12 7e }

  condition:
    any of them
}