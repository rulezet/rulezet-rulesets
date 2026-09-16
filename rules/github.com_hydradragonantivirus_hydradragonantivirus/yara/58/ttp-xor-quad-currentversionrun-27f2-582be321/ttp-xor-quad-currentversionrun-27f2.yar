rule TTP_XOR_QUAD_CurrentVersionRun_27f2 {
  strings:
    $key_27f2 = { 74 9d [2] 50 93 [2] 7b bf [2] 55 9d [2] 41 86 [2] 4e 9c [2] 50 81 [2] 52 80 [2] 49 86 [2] 55 81 [2] 49 ae }

  condition:
    any of them
}