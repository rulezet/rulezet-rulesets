rule TTP_XOR_QUAD_CurrentVersionRun_4640 {
  strings:
    $key_4640 = { 15 2f [2] 31 21 [2] 1a 0d [2] 34 2f [2] 20 34 [2] 2f 2e [2] 31 33 [2] 33 32 [2] 28 34 [2] 34 33 [2] 28 1c }

  condition:
    any of them
}