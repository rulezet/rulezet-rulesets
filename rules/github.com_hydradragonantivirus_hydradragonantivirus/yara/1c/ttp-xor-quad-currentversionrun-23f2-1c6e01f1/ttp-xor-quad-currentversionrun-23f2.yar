rule TTP_XOR_QUAD_CurrentVersionRun_23f2 {
  strings:
    $key_23f2 = { 70 9d [2] 54 93 [2] 7f bf [2] 51 9d [2] 45 86 [2] 4a 9c [2] 54 81 [2] 56 80 [2] 4d 86 [2] 51 81 [2] 4d ae }

  condition:
    any of them
}