rule TTP_XOR_QUAD_CurrentVersionRun_fc63 {
  strings:
    $key_fc63 = { af 0c [2] 8b 02 [2] a0 2e [2] 8e 0c [2] 9a 17 [2] 95 0d [2] 8b 10 [2] 89 11 [2] 92 17 [2] 8e 10 [2] 92 3f }

  condition:
    any of them
}