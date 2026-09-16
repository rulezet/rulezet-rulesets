rule TTP_XOR_QUAD_CurrentVersionRun_bcfe {
  strings:
    $key_bcfe = { ef 91 [2] cb 9f [2] e0 b3 [2] ce 91 [2] da 8a [2] d5 90 [2] cb 8d [2] c9 8c [2] d2 8a [2] ce 8d [2] d2 a2 }

  condition:
    any of them
}