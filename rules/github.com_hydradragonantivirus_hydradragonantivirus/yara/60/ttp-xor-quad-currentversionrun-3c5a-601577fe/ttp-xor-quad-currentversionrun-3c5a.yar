rule TTP_XOR_QUAD_CurrentVersionRun_3c5a {
  strings:
    $key_3c5a = { 6f 35 [2] 4b 3b [2] 60 17 [2] 4e 35 [2] 5a 2e [2] 55 34 [2] 4b 29 [2] 49 28 [2] 52 2e [2] 4e 29 [2] 52 06 }

  condition:
    any of them
}