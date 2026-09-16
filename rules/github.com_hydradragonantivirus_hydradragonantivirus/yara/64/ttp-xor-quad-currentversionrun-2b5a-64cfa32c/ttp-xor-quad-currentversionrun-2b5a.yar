rule TTP_XOR_QUAD_CurrentVersionRun_2b5a {
  strings:
    $key_2b5a = { 78 35 [2] 5c 3b [2] 77 17 [2] 59 35 [2] 4d 2e [2] 42 34 [2] 5c 29 [2] 5e 28 [2] 45 2e [2] 59 29 [2] 45 06 }

  condition:
    any of them
}