rule TTP_XOR_QUAD_CurrentVersionRun_a0f2 {
  strings:
    $key_a0f2 = { f3 9d [2] d7 93 [2] fc bf [2] d2 9d [2] c6 86 [2] c9 9c [2] d7 81 [2] d5 80 [2] ce 86 [2] d2 81 [2] ce ae }

  condition:
    any of them
}