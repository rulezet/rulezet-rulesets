rule TTP_XOR_QUAD_CurrentVersionRun_a7f2 {
  strings:
    $key_a7f2 = { f4 9d [2] d0 93 [2] fb bf [2] d5 9d [2] c1 86 [2] ce 9c [2] d0 81 [2] d2 80 [2] c9 86 [2] d5 81 [2] c9 ae }

  condition:
    any of them
}