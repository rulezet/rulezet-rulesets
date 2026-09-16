rule TTP_XOR_QUAD_CurrentVersionRun_bc14 {
  strings:
    $key_bc14 = { ef 7b [2] cb 75 [2] e0 59 [2] ce 7b [2] da 60 [2] d5 7a [2] cb 67 [2] c9 66 [2] d2 60 [2] ce 67 [2] d2 48 }

  condition:
    any of them
}