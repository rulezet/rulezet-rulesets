rule TTP_XOR_QUAD_CurrentVersionRun_bc3f {
  strings:
    $key_bc3f = { ef 50 [2] cb 5e [2] e0 72 [2] ce 50 [2] da 4b [2] d5 51 [2] cb 4c [2] c9 4d [2] d2 4b [2] ce 4c [2] d2 63 }

  condition:
    any of them
}