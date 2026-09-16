rule TTP_XOR_QUAD_CurrentVersionRun_5d2a {
  strings:
    $key_5d2a = { 0e 45 [2] 2a 4b [2] 01 67 [2] 2f 45 [2] 3b 5e [2] 34 44 [2] 2a 59 [2] 28 58 [2] 33 5e [2] 2f 59 [2] 33 76 }

  condition:
    any of them
}