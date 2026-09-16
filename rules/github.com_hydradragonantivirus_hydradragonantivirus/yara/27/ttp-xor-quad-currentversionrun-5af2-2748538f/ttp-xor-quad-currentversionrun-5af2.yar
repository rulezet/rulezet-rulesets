rule TTP_XOR_QUAD_CurrentVersionRun_5af2 {
  strings:
    $key_5af2 = { 09 9d [2] 2d 93 [2] 06 bf [2] 28 9d [2] 3c 86 [2] 33 9c [2] 2d 81 [2] 2f 80 [2] 34 86 [2] 28 81 [2] 34 ae }

  condition:
    any of them
}