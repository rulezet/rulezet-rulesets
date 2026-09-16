rule TTP_XOR_QUAD_CurrentVersionRun_2e2a {
  strings:
    $key_2e2a = { 7d 45 [2] 59 4b [2] 72 67 [2] 5c 45 [2] 48 5e [2] 47 44 [2] 59 59 [2] 5b 58 [2] 40 5e [2] 5c 59 [2] 40 76 }

  condition:
    any of them
}