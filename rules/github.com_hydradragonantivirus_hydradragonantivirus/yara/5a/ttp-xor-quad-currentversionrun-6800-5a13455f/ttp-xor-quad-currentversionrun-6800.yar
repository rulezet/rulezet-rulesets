rule TTP_XOR_QUAD_CurrentVersionRun_6800 {
  strings:
    $key_6800 = { 3b 6f [2] 1f 61 [2] 34 4d [2] 1a 6f [2] 0e 74 [2] 01 6e [2] 1f 73 [2] 1d 72 [2] 06 74 [2] 1a 73 [2] 06 5c }

  condition:
    any of them
}