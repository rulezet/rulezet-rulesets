rule TTP_XOR_QUAD_CurrentVersionRun_bc33 {
  strings:
    $key_bc33 = { ef 5c [2] cb 52 [2] e0 7e [2] ce 5c [2] da 47 [2] d5 5d [2] cb 40 [2] c9 41 [2] d2 47 [2] ce 40 [2] d2 6f }

  condition:
    any of them
}