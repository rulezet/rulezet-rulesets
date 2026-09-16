rule TTP_XOR_QUAD_CurrentVersionRun_5d1d {
  strings:
    $key_5d1d = { 0e 72 [2] 2a 7c [2] 01 50 [2] 2f 72 [2] 3b 69 [2] 34 73 [2] 2a 6e [2] 28 6f [2] 33 69 [2] 2f 6e [2] 33 41 }

  condition:
    any of them
}