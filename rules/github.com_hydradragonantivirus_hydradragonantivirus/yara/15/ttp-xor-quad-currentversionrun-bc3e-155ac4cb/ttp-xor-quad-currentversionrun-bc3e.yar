rule TTP_XOR_QUAD_CurrentVersionRun_bc3e {
  strings:
    $key_bc3e = { ef 51 [2] cb 5f [2] e0 73 [2] ce 51 [2] da 4a [2] d5 50 [2] cb 4d [2] c9 4c [2] d2 4a [2] ce 4d [2] d2 62 }

  condition:
    any of them
}