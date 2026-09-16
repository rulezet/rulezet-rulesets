rule TTP_XOR_QUAD_CurrentVersionRun_e8f2 {
  strings:
    $key_e8f2 = { bb 9d [2] 9f 93 [2] b4 bf [2] 9a 9d [2] 8e 86 [2] 81 9c [2] 9f 81 [2] 9d 80 [2] 86 86 [2] 9a 81 [2] 86 ae }

  condition:
    any of them
}