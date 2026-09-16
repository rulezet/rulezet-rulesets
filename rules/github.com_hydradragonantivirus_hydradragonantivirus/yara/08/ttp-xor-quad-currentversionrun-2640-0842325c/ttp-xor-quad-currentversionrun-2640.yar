rule TTP_XOR_QUAD_CurrentVersionRun_2640 {
  strings:
    $key_2640 = { 75 2f [2] 51 21 [2] 7a 0d [2] 54 2f [2] 40 34 [2] 4f 2e [2] 51 33 [2] 53 32 [2] 48 34 [2] 54 33 [2] 48 1c }

  condition:
    any of them
}