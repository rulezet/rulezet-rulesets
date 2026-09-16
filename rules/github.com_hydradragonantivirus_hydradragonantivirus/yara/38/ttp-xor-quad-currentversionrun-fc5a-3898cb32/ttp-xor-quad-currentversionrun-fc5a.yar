rule TTP_XOR_QUAD_CurrentVersionRun_fc5a {
  strings:
    $key_fc5a = { af 35 [2] 8b 3b [2] a0 17 [2] 8e 35 [2] 9a 2e [2] 95 34 [2] 8b 29 [2] 89 28 [2] 92 2e [2] 8e 29 [2] 92 06 }

  condition:
    any of them
}