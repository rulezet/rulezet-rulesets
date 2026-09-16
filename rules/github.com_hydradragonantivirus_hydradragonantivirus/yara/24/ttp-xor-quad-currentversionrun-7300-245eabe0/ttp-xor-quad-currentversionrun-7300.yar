rule TTP_XOR_QUAD_CurrentVersionRun_7300 {
  strings:
    $key_7300 = { 20 6f [2] 04 61 [2] 2f 4d [2] 01 6f [2] 15 74 [2] 1a 6e [2] 04 73 [2] 06 72 [2] 1d 74 [2] 01 73 [2] 1d 5c }

  condition:
    any of them
}