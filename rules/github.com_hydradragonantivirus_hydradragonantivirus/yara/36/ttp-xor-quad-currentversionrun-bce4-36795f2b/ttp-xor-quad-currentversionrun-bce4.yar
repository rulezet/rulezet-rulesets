rule TTP_XOR_QUAD_CurrentVersionRun_bce4 {
  strings:
    $key_bce4 = { ef 8b [2] cb 85 [2] e0 a9 [2] ce 8b [2] da 90 [2] d5 8a [2] cb 97 [2] c9 96 [2] d2 90 [2] ce 97 [2] d2 b8 }

  condition:
    any of them
}