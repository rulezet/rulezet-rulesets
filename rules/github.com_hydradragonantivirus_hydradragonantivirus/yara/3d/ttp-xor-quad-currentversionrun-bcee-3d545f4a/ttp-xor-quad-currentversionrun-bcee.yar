rule TTP_XOR_QUAD_CurrentVersionRun_bcee {
  strings:
    $key_bcee = { ef 81 [2] cb 8f [2] e0 a3 [2] ce 81 [2] da 9a [2] d5 80 [2] cb 9d [2] c9 9c [2] d2 9a [2] ce 9d [2] d2 b2 }

  condition:
    any of them
}