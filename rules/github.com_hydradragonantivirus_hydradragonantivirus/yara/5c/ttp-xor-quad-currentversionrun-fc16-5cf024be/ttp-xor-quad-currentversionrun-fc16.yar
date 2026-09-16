rule TTP_XOR_QUAD_CurrentVersionRun_fc16 {
  strings:
    $key_fc16 = { af 79 [2] 8b 77 [2] a0 5b [2] 8e 79 [2] 9a 62 [2] 95 78 [2] 8b 65 [2] 89 64 [2] 92 62 [2] 8e 65 [2] 92 4a }

  condition:
    any of them
}