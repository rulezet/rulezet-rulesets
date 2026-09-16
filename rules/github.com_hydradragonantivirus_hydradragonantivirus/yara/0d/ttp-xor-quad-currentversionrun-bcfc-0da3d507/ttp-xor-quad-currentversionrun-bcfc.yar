rule TTP_XOR_QUAD_CurrentVersionRun_bcfc {
  strings:
    $key_bcfc = { ef 93 [2] cb 9d [2] e0 b1 [2] ce 93 [2] da 88 [2] d5 92 [2] cb 8f [2] c9 8e [2] d2 88 [2] ce 8f [2] d2 a0 }

  condition:
    any of them
}