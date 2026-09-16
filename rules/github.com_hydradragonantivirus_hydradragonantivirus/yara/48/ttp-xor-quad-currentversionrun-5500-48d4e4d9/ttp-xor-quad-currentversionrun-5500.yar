rule TTP_XOR_QUAD_CurrentVersionRun_5500 {
  strings:
    $key_5500 = { 06 6f [2] 22 61 [2] 09 4d [2] 27 6f [2] 33 74 [2] 3c 6e [2] 22 73 [2] 20 72 [2] 3b 74 [2] 27 73 [2] 3b 5c }

  condition:
    any of them
}