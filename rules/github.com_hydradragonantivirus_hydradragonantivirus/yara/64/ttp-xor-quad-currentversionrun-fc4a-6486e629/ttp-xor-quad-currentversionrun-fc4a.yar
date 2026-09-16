rule TTP_XOR_QUAD_CurrentVersionRun_fc4a {
  strings:
    $key_fc4a = { af 25 [2] 8b 2b [2] a0 07 [2] 8e 25 [2] 9a 3e [2] 95 24 [2] 8b 39 [2] 89 38 [2] 92 3e [2] 8e 39 [2] 92 16 }

  condition:
    any of them
}