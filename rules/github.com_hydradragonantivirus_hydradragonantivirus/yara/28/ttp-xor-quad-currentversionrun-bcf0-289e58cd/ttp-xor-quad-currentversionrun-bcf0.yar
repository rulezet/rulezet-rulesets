rule TTP_XOR_QUAD_CurrentVersionRun_bcf0 {
  strings:
    $key_bcf0 = { ef 9f [2] cb 91 [2] e0 bd [2] ce 9f [2] da 84 [2] d5 9e [2] cb 83 [2] c9 82 [2] d2 84 [2] ce 83 [2] d2 ac }

  condition:
    any of them
}