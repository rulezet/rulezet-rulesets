rule TTP_XOR_QUAD_CurrentVersionRun_bc4c {
  strings:
    $key_bc4c = { ef 23 [2] cb 2d [2] e0 01 [2] ce 23 [2] da 38 [2] d5 22 [2] cb 3f [2] c9 3e [2] d2 38 [2] ce 3f [2] d2 10 }

  condition:
    any of them
}