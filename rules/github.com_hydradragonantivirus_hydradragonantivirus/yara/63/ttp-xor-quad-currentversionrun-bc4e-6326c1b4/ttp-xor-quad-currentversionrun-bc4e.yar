rule TTP_XOR_QUAD_CurrentVersionRun_bc4e {
  strings:
    $key_bc4e = { ef 21 [2] cb 2f [2] e0 03 [2] ce 21 [2] da 3a [2] d5 20 [2] cb 3d [2] c9 3c [2] d2 3a [2] ce 3d [2] d2 12 }

  condition:
    any of them
}