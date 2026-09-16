rule TTP_XOR_QUAD_CurrentVersionRun_fc31 {
  strings:
    $key_fc31 = { af 5e [2] 8b 50 [2] a0 7c [2] 8e 5e [2] 9a 45 [2] 95 5f [2] 8b 42 [2] 89 43 [2] 92 45 [2] 8e 42 [2] 92 6d }

  condition:
    any of them
}