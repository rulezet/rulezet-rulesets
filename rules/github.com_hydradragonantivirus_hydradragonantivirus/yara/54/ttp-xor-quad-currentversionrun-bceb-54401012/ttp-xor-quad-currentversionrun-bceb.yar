rule TTP_XOR_QUAD_CurrentVersionRun_bceb {
  strings:
    $key_bceb = { ef 84 [2] cb 8a [2] e0 a6 [2] ce 84 [2] da 9f [2] d5 85 [2] cb 98 [2] c9 99 [2] d2 9f [2] ce 98 [2] d2 b7 }

  condition:
    any of them
}