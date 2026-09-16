rule TTP_XOR_QUAD_CurrentVersionRun_54f2 {
  strings:
    $key_54f2 = { 07 9d [2] 23 93 [2] 08 bf [2] 26 9d [2] 32 86 [2] 3d 9c [2] 23 81 [2] 21 80 [2] 3a 86 [2] 26 81 [2] 3a ae }

  condition:
    any of them
}