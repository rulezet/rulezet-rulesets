rule TTP_XOR_QUAD_CurrentVersionRun_75f2 {
  strings:
    $key_75f2 = { 26 9d [2] 02 93 [2] 29 bf [2] 07 9d [2] 13 86 [2] 1c 9c [2] 02 81 [2] 00 80 [2] 1b 86 [2] 07 81 [2] 1b ae }

  condition:
    any of them
}