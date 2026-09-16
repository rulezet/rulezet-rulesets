rule TTP_XOR_QUAD_CurrentVersionRun_472a {
  strings:
    $key_472a = { 14 45 [2] 30 4b [2] 1b 67 [2] 35 45 [2] 21 5e [2] 2e 44 [2] 30 59 [2] 32 58 [2] 29 5e [2] 35 59 [2] 29 76 }

  condition:
    any of them
}