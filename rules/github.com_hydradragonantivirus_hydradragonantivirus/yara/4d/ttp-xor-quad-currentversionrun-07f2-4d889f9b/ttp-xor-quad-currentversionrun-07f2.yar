rule TTP_XOR_QUAD_CurrentVersionRun_07f2 {
  strings:
    $key_07f2 = { 54 9d [2] 70 93 [2] 5b bf [2] 75 9d [2] 61 86 [2] 6e 9c [2] 70 81 [2] 72 80 [2] 69 86 [2] 75 81 [2] 69 ae }

  condition:
    any of them
}