rule TTP_XOR_QUAD_CurrentVersionRun_bc6e {
  strings:
    $key_bc6e = { ef 01 [2] cb 0f [2] e0 23 [2] ce 01 [2] da 1a [2] d5 00 [2] cb 1d [2] c9 1c [2] d2 1a [2] ce 1d [2] d2 32 }

  condition:
    any of them
}