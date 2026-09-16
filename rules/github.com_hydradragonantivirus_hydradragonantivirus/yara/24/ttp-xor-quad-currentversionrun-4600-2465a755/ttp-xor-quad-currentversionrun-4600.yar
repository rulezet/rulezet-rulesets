rule TTP_XOR_QUAD_CurrentVersionRun_4600 {
  strings:
    $key_4600 = { 15 6f [2] 31 61 [2] 1a 4d [2] 34 6f [2] 20 74 [2] 2f 6e [2] 31 73 [2] 33 72 [2] 28 74 [2] 34 73 [2] 28 5c }

  condition:
    any of them
}