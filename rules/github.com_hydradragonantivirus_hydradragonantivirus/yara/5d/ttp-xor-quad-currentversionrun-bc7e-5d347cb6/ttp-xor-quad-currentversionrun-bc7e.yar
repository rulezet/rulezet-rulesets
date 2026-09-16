rule TTP_XOR_QUAD_CurrentVersionRun_bc7e {
  strings:
    $key_bc7e = { ef 11 [2] cb 1f [2] e0 33 [2] ce 11 [2] da 0a [2] d5 10 [2] cb 0d [2] c9 0c [2] d2 0a [2] ce 0d [2] d2 22 }

  condition:
    any of them
}