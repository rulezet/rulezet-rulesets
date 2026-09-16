rule TTP_XOR_QUAD_CurrentVersionRun_a2f2 {
  strings:
    $key_a2f2 = { f1 9d [2] d5 93 [2] fe bf [2] d0 9d [2] c4 86 [2] cb 9c [2] d5 81 [2] d7 80 [2] cc 86 [2] d0 81 [2] cc ae }

  condition:
    any of them
}