rule TTP_XOR_QUAD_CurrentVersionRun_bc21 {
  strings:
    $key_bc21 = { ef 4e [2] cb 40 [2] e0 6c [2] ce 4e [2] da 55 [2] d5 4f [2] cb 52 [2] c9 53 [2] d2 55 [2] ce 52 [2] d2 7d }

  condition:
    any of them
}