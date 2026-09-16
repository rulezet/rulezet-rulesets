rule TTP_XOR_QUAD_CurrentVersionRun_bc0f {
  strings:
    $key_bc0f = { ef 60 [2] cb 6e [2] e0 42 [2] ce 60 [2] da 7b [2] d5 61 [2] cb 7c [2] c9 7d [2] d2 7b [2] ce 7c [2] d2 53 }

  condition:
    any of them
}