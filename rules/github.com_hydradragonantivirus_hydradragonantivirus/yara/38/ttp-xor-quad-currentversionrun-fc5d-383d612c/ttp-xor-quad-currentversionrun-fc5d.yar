rule TTP_XOR_QUAD_CurrentVersionRun_fc5d {
  strings:
    $key_fc5d = { af 32 [2] 8b 3c [2] a0 10 [2] 8e 32 [2] 9a 29 [2] 95 33 [2] 8b 2e [2] 89 2f [2] 92 29 [2] 8e 2e [2] 92 01 }

  condition:
    any of them
}