rule TTP_XOR_QUAD_CurrentVersionRun_7550 {
  strings:
    $key_7550 = { 26 3f [2] 02 31 [2] 29 1d [2] 07 3f [2] 13 24 [2] 1c 3e [2] 02 23 [2] 00 22 [2] 1b 24 [2] 07 23 [2] 1b 0c }

  condition:
    any of them
}