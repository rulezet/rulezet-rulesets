rule TTP_XOR_QUAD_CurrentVersionRun_bbf2 {
  strings:
    $key_bbf2 = { e8 9d [2] cc 93 [2] e7 bf [2] c9 9d [2] dd 86 [2] d2 9c [2] cc 81 [2] ce 80 [2] d5 86 [2] c9 81 [2] d5 ae }

  condition:
    any of them
}