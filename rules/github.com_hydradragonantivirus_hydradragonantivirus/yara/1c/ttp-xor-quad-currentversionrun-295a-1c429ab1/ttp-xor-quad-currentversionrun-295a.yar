rule TTP_XOR_QUAD_CurrentVersionRun_295a {
  strings:
    $key_295a = { 7a 35 [2] 5e 3b [2] 75 17 [2] 5b 35 [2] 4f 2e [2] 40 34 [2] 5e 29 [2] 5c 28 [2] 47 2e [2] 5b 29 [2] 47 06 }

  condition:
    any of them
}