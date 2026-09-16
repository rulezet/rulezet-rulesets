rule TTP_XOR_QUAD_CurrentVersionRun_4ff2 {
  strings:
    $key_4ff2 = { 1c 9d [2] 38 93 [2] 13 bf [2] 3d 9d [2] 29 86 [2] 26 9c [2] 38 81 [2] 3a 80 [2] 21 86 [2] 3d 81 [2] 21 ae }

  condition:
    any of them
}