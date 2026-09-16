rule TTP_XOR_QUAD_CurrentVersionRun_bc0c {
  strings:
    $key_bc0c = { ef 63 [2] cb 6d [2] e0 41 [2] ce 63 [2] da 78 [2] d5 62 [2] cb 7f [2] c9 7e [2] d2 78 [2] ce 7f [2] d2 50 }

  condition:
    any of them
}