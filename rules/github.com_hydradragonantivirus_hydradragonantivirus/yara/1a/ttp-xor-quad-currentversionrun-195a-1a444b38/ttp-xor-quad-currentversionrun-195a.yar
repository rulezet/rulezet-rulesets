rule TTP_XOR_QUAD_CurrentVersionRun_195a {
  strings:
    $key_195a = { 4a 35 [2] 6e 3b [2] 45 17 [2] 6b 35 [2] 7f 2e [2] 70 34 [2] 6e 29 [2] 6c 28 [2] 77 2e [2] 6b 29 [2] 77 06 }

  condition:
    any of them
}