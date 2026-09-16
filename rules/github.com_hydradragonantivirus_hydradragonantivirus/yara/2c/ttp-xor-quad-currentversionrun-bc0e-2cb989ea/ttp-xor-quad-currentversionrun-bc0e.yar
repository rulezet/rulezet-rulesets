rule TTP_XOR_QUAD_CurrentVersionRun_bc0e {
  strings:
    $key_bc0e = { ef 61 [2] cb 6f [2] e0 43 [2] ce 61 [2] da 7a [2] d5 60 [2] cb 7d [2] c9 7c [2] d2 7a [2] ce 7d [2] d2 52 }

  condition:
    any of them
}