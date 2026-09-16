rule TTP_XOR_QUAD_CurrentVersionRun_2e5a {
  strings:
    $key_2e5a = { 7d 35 [2] 59 3b [2] 72 17 [2] 5c 35 [2] 48 2e [2] 47 34 [2] 59 29 [2] 5b 28 [2] 40 2e [2] 5c 29 [2] 40 06 }

  condition:
    any of them
}