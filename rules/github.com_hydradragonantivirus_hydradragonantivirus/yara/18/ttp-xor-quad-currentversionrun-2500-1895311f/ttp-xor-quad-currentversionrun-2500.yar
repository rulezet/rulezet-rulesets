rule TTP_XOR_QUAD_CurrentVersionRun_2500 {
  strings:
    $key_2500 = { 76 6f [2] 52 61 [2] 79 4d [2] 57 6f [2] 43 74 [2] 4c 6e [2] 52 73 [2] 50 72 [2] 4b 74 [2] 57 73 [2] 4b 5c }

  condition:
    any of them
}