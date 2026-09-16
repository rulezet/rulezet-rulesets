rule TTP_XOR_QUAD_CurrentVersionRun_5d50 {
  strings:
    $key_5d50 = { 0e 3f [2] 2a 31 [2] 01 1d [2] 2f 3f [2] 3b 24 [2] 34 3e [2] 2a 23 [2] 28 22 [2] 33 24 [2] 2f 23 [2] 33 0c }

  condition:
    any of them
}