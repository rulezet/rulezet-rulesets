rule TTP_XOR_QUAD_CurrentVersionRun_18f2 {
  strings:
    $key_18f2 = { 4b 9d [2] 6f 93 [2] 44 bf [2] 6a 9d [2] 7e 86 [2] 71 9c [2] 6f 81 [2] 6d 80 [2] 76 86 [2] 6a 81 [2] 76 ae }

  condition:
    any of them
}