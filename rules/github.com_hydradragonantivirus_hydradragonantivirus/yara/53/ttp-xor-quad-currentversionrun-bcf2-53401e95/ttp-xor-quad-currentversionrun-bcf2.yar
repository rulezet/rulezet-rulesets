rule TTP_XOR_QUAD_CurrentVersionRun_bcf2 {
  strings:
    $key_bcf2 = { ef 9d [2] cb 93 [2] e0 bf [2] ce 9d [2] da 86 [2] d5 9c [2] cb 81 [2] c9 80 [2] d2 86 [2] ce 81 [2] d2 ae }

  condition:
    any of them
}