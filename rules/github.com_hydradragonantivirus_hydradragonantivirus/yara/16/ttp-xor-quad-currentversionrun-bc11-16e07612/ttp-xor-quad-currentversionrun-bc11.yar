rule TTP_XOR_QUAD_CurrentVersionRun_bc11 {
  strings:
    $key_bc11 = { ef 7e [2] cb 70 [2] e0 5c [2] ce 7e [2] da 65 [2] d5 7f [2] cb 62 [2] c9 63 [2] d2 65 [2] ce 62 [2] d2 4d }

  condition:
    any of them
}