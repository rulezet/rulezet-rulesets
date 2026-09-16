rule TTP_XOR_QUAD_CurrentVersionRun_d4f2 {
  strings:
    $key_d4f2 = { 87 9d [2] a3 93 [2] 88 bf [2] a6 9d [2] b2 86 [2] bd 9c [2] a3 81 [2] a1 80 [2] ba 86 [2] a6 81 [2] ba ae }

  condition:
    any of them
}