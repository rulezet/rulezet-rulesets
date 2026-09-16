rule TTP_XOR_QUAD_CurrentVersionRun_bc2a {
  strings:
    $key_bc2a = { ef 45 [2] cb 4b [2] e0 67 [2] ce 45 [2] da 5e [2] d5 44 [2] cb 59 [2] c9 58 [2] d2 5e [2] ce 59 [2] d2 76 }

  condition:
    any of them
}