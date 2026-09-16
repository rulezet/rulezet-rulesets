rule TTP_XOR_QUAD_CurrentVersionRun_4700 {
  strings:
    $key_4700 = { 14 6f [2] 30 61 [2] 1b 4d [2] 35 6f [2] 21 74 [2] 2e 6e [2] 30 73 [2] 32 72 [2] 29 74 [2] 35 73 [2] 29 5c }

  condition:
    any of them
}