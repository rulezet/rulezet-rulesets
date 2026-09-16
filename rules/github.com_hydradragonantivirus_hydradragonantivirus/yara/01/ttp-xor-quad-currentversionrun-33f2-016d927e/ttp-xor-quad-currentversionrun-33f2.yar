rule TTP_XOR_QUAD_CurrentVersionRun_33f2 {
  strings:
    $key_33f2 = { 60 9d [2] 44 93 [2] 6f bf [2] 41 9d [2] 55 86 [2] 5a 9c [2] 44 81 [2] 46 80 [2] 5d 86 [2] 41 81 [2] 5d ae }

  condition:
    any of them
}