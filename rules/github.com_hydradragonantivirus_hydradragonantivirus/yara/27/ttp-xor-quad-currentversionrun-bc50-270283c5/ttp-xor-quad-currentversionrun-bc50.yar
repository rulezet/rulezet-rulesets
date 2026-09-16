rule TTP_XOR_QUAD_CurrentVersionRun_bc50 {
  strings:
    $key_bc50 = { ef 3f [2] cb 31 [2] e0 1d [2] ce 3f [2] da 24 [2] d5 3e [2] cb 23 [2] c9 22 [2] d2 24 [2] ce 23 [2] d2 0c }

  condition:
    any of them
}