rule TTP_XOR_QUAD_CurrentVersionRun_bc7c {
  strings:
    $key_bc7c = { ef 13 [2] cb 1d [2] e0 31 [2] ce 13 [2] da 08 [2] d5 12 [2] cb 0f [2] c9 0e [2] d2 08 [2] ce 0f [2] d2 20 }

  condition:
    any of them
}