rule TTP_XOR_QUAD_CurrentVersionRun_25f2 {
  strings:
    $key_25f2 = { 76 9d [2] 52 93 [2] 79 bf [2] 57 9d [2] 43 86 [2] 4c 9c [2] 52 81 [2] 50 80 [2] 4b 86 [2] 57 81 [2] 4b ae }

  condition:
    any of them
}