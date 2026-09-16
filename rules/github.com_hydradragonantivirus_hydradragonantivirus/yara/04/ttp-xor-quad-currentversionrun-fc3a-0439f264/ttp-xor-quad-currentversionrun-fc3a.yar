rule TTP_XOR_QUAD_CurrentVersionRun_fc3a {
  strings:
    $key_fc3a = { af 55 [2] 8b 5b [2] a0 77 [2] 8e 55 [2] 9a 4e [2] 95 54 [2] 8b 49 [2] 89 48 [2] 92 4e [2] 8e 49 [2] 92 66 }

  condition:
    any of them
}