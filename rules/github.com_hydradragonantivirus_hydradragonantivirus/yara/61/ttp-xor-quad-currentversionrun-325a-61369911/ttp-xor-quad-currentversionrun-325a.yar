rule TTP_XOR_QUAD_CurrentVersionRun_325a {
  strings:
    $key_325a = { 61 35 [2] 45 3b [2] 6e 17 [2] 40 35 [2] 54 2e [2] 5b 34 [2] 45 29 [2] 47 28 [2] 5c 2e [2] 40 29 [2] 5c 06 }

  condition:
    any of them
}