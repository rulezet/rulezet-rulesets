rule TTP_XOR_QUAD_CurrentVersionRun_68f2 {
  strings:
    $key_68f2 = { 3b 9d [2] 1f 93 [2] 34 bf [2] 1a 9d [2] 0e 86 [2] 01 9c [2] 1f 81 [2] 1d 80 [2] 06 86 [2] 1a 81 [2] 06 ae }

  condition:
    any of them
}