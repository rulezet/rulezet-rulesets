rule TTP_XOR_QUAD_CurrentVersionRun_562a {
  strings:
    $key_562a = { 05 45 [2] 21 4b [2] 0a 67 [2] 24 45 [2] 30 5e [2] 3f 44 [2] 21 59 [2] 23 58 [2] 38 5e [2] 24 59 [2] 38 76 }

  condition:
    any of them
}