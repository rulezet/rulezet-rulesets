rule TTP_XOR_QUAD_CurrentVersionRun_fc56 {
  strings:
    $key_fc56 = { af 39 [2] 8b 37 [2] a0 1b [2] 8e 39 [2] 9a 22 [2] 95 38 [2] 8b 25 [2] 89 24 [2] 92 22 [2] 8e 25 [2] 92 0a }

  condition:
    any of them
}