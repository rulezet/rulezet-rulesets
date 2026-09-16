rule TTP_XOR_QUAD_CurrentVersionRun_47f2 {
  strings:
    $key_47f2 = { 14 9d [2] 30 93 [2] 1b bf [2] 35 9d [2] 21 86 [2] 2e 9c [2] 30 81 [2] 32 80 [2] 29 86 [2] 35 81 [2] 29 ae }

  condition:
    any of them
}