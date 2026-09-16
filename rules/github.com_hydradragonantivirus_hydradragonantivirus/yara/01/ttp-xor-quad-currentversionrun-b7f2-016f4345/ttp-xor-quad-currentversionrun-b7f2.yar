rule TTP_XOR_QUAD_CurrentVersionRun_b7f2 {
  strings:
    $key_b7f2 = { e4 9d [2] c0 93 [2] eb bf [2] c5 9d [2] d1 86 [2] de 9c [2] c0 81 [2] c2 80 [2] d9 86 [2] c5 81 [2] d9 ae }

  condition:
    any of them
}