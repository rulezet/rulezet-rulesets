rule TTP_XOR_QUAD_CurrentVersionRun_5140 {
  strings:
    $key_5140 = { 02 2f [2] 26 21 [2] 0d 0d [2] 23 2f [2] 37 34 [2] 38 2e [2] 26 33 [2] 24 32 [2] 3f 34 [2] 23 33 [2] 3f 1c }

  condition:
    any of them
}