rule TTP_XOR_QUAD_CurrentVersionRun_7500 {
  strings:
    $key_7500 = { 26 6f [2] 02 61 [2] 29 4d [2] 07 6f [2] 13 74 [2] 1c 6e [2] 02 73 [2] 00 72 [2] 1b 74 [2] 07 73 [2] 1b 5c }

  condition:
    any of them
}