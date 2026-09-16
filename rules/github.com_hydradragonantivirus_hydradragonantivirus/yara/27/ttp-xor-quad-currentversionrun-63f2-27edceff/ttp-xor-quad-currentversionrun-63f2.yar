rule TTP_XOR_QUAD_CurrentVersionRun_63f2 {
  strings:
    $key_63f2 = { 30 9d [2] 14 93 [2] 3f bf [2] 11 9d [2] 05 86 [2] 0a 9c [2] 14 81 [2] 16 80 [2] 0d 86 [2] 11 81 [2] 0d ae }

  condition:
    any of them
}