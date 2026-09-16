rule TTP_XOR_QUAD_CurrentVersionRun_7af2 {
  strings:
    $key_7af2 = { 29 9d [2] 0d 93 [2] 26 bf [2] 08 9d [2] 1c 86 [2] 13 9c [2] 0d 81 [2] 0f 80 [2] 14 86 [2] 08 81 [2] 14 ae }

  condition:
    any of them
}