rule TTP_XOR_QUAD_CurrentVersionRun_39f2 {
  strings:
    $key_39f2 = { 6a 9d [2] 4e 93 [2] 65 bf [2] 4b 9d [2] 5f 86 [2] 50 9c [2] 4e 81 [2] 4c 80 [2] 57 86 [2] 4b 81 [2] 57 ae }

  condition:
    any of them
}