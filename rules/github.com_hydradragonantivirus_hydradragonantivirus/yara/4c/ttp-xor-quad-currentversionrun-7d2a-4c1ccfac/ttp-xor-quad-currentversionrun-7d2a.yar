rule TTP_XOR_QUAD_CurrentVersionRun_7d2a {
  strings:
    $key_7d2a = { 2e 45 [2] 0a 4b [2] 21 67 [2] 0f 45 [2] 1b 5e [2] 14 44 [2] 0a 59 [2] 08 58 [2] 13 5e [2] 0f 59 [2] 13 76 }

  condition:
    any of them
}