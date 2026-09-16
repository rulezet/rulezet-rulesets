rule TTP_XOR_QUAD_CurrentVersionRun_bc6d {
  strings:
    $key_bc6d = { ef 02 [2] cb 0c [2] e0 20 [2] ce 02 [2] da 19 [2] d5 03 [2] cb 1e [2] c9 1f [2] d2 19 [2] ce 1e [2] d2 31 }

  condition:
    any of them
}