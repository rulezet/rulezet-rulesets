rule TTP_XOR_QUAD_CurrentVersionRun_64f2 {
  strings:
    $key_64f2 = { 37 9d [2] 13 93 [2] 38 bf [2] 16 9d [2] 02 86 [2] 0d 9c [2] 13 81 [2] 11 80 [2] 0a 86 [2] 16 81 [2] 0a ae }

  condition:
    any of them
}