rule TTP_XOR_QUAD_CurrentVersionRun_b3f2 {
  strings:
    $key_b3f2 = { e0 9d [2] c4 93 [2] ef bf [2] c1 9d [2] d5 86 [2] da 9c [2] c4 81 [2] c6 80 [2] dd 86 [2] c1 81 [2] dd ae }

  condition:
    any of them
}