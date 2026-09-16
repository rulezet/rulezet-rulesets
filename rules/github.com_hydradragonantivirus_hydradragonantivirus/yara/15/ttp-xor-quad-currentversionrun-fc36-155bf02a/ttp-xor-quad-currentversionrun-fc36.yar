rule TTP_XOR_QUAD_CurrentVersionRun_fc36 {
  strings:
    $key_fc36 = { af 59 [2] 8b 57 [2] a0 7b [2] 8e 59 [2] 9a 42 [2] 95 58 [2] 8b 45 [2] 89 44 [2] 92 42 [2] 8e 45 [2] 92 6a }

  condition:
    any of them
}