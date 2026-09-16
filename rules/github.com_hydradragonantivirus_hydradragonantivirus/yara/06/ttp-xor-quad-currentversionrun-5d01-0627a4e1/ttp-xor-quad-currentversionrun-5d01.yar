rule TTP_XOR_QUAD_CurrentVersionRun_5d01 {
  strings:
    $key_5d01 = { 0e 6e [2] 2a 60 [2] 01 4c [2] 2f 6e [2] 3b 75 [2] 34 6f [2] 2a 72 [2] 28 73 [2] 33 75 [2] 2f 72 [2] 33 5d }

  condition:
    any of them
}