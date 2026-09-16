rule TTP_XOR_QUAD_CurrentVersionRun_bc0a {
  strings:
    $key_bc0a = { ef 65 [2] cb 6b [2] e0 47 [2] ce 65 [2] da 7e [2] d5 64 [2] cb 79 [2] c9 78 [2] d2 7e [2] ce 79 [2] d2 56 }

  condition:
    any of them
}