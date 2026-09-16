rule TTP_XOR_QUAD_CurrentVersionRun_4d2a {
  strings:
    $key_4d2a = { 1e 45 [2] 3a 4b [2] 11 67 [2] 3f 45 [2] 2b 5e [2] 24 44 [2] 3a 59 [2] 38 58 [2] 23 5e [2] 3f 59 [2] 23 76 }

  condition:
    any of them
}