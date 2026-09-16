rule TTP_XOR_QUAD_CurrentVersionRun_625a {
  strings:
    $key_625a = { 31 35 [2] 15 3b [2] 3e 17 [2] 10 35 [2] 04 2e [2] 0b 34 [2] 15 29 [2] 17 28 [2] 0c 2e [2] 10 29 [2] 0c 06 }

  condition:
    any of them
}