rule TTP_XOR_QUAD_CurrentVersionRun_fc41 {
  strings:
    $key_fc41 = { af 2e [2] 8b 20 [2] a0 0c [2] 8e 2e [2] 9a 35 [2] 95 2f [2] 8b 32 [2] 89 33 [2] 92 35 [2] 8e 32 [2] 92 1d }

  condition:
    any of them
}