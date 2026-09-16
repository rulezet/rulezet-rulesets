rule TTP_XOR_QUAD_CurrentVersionRun_4af2 {
  strings:
    $key_4af2 = { 19 9d [2] 3d 93 [2] 16 bf [2] 38 9d [2] 2c 86 [2] 23 9c [2] 3d 81 [2] 3f 80 [2] 24 86 [2] 38 81 [2] 24 ae }

  condition:
    any of them
}