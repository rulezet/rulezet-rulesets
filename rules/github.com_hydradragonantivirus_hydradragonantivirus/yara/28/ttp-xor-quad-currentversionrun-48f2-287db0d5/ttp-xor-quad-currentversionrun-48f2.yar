rule TTP_XOR_QUAD_CurrentVersionRun_48f2 {
  strings:
    $key_48f2 = { 1b 9d [2] 3f 93 [2] 14 bf [2] 3a 9d [2] 2e 86 [2] 21 9c [2] 3f 81 [2] 3d 80 [2] 26 86 [2] 3a 81 [2] 26 ae }

  condition:
    any of them
}