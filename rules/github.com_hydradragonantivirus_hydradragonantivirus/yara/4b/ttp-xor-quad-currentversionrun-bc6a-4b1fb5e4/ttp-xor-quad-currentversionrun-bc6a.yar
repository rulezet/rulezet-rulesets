rule TTP_XOR_QUAD_CurrentVersionRun_bc6a {
  strings:
    $key_bc6a = { ef 05 [2] cb 0b [2] e0 27 [2] ce 05 [2] da 1e [2] d5 04 [2] cb 19 [2] c9 18 [2] d2 1e [2] ce 19 [2] d2 36 }

  condition:
    any of them
}