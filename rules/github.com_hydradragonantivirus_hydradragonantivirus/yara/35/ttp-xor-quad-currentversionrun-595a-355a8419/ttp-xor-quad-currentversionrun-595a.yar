rule TTP_XOR_QUAD_CurrentVersionRun_595a {
  strings:
    $key_595a = { 0a 35 [2] 2e 3b [2] 05 17 [2] 2b 35 [2] 3f 2e [2] 30 34 [2] 2e 29 [2] 2c 28 [2] 37 2e [2] 2b 29 [2] 37 06 }

  condition:
    any of them
}