rule TTP_XOR_QUAD_CurrentVersionRun_6000 {
  strings:
    $key_6000 = { 33 6f [2] 17 61 [2] 3c 4d [2] 12 6f [2] 06 74 [2] 09 6e [2] 17 73 [2] 15 72 [2] 0e 74 [2] 12 73 [2] 0e 5c }

  condition:
    any of them
}