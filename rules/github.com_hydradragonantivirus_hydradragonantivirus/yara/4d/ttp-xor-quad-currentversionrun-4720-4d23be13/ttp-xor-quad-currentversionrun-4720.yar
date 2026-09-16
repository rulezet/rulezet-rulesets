rule TTP_XOR_QUAD_CurrentVersionRun_4720 {
  strings:
    $key_4720 = { 14 4f [2] 30 41 [2] 1b 6d [2] 35 4f [2] 21 54 [2] 2e 4e [2] 30 53 [2] 32 52 [2] 29 54 [2] 35 53 [2] 29 7c }

  condition:
    any of them
}