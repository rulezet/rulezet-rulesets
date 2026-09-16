rule TTP_XOR_QUAD_CurrentVersionRun_fc40 {
  strings:
    $key_fc40 = { af 2f [2] 8b 21 [2] a0 0d [2] 8e 2f [2] 9a 34 [2] 95 2e [2] 8b 33 [2] 89 32 [2] 92 34 [2] 8e 33 [2] 92 1c }

  condition:
    any of them
}