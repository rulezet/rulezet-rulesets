rule TTP_XOR_QUAD_CurrentVersionRun_bc31 {
  strings:
    $key_bc31 = { ef 5e [2] cb 50 [2] e0 7c [2] ce 5e [2] da 45 [2] d5 5f [2] cb 42 [2] c9 43 [2] d2 45 [2] ce 42 [2] d2 6d }

  condition:
    any of them
}