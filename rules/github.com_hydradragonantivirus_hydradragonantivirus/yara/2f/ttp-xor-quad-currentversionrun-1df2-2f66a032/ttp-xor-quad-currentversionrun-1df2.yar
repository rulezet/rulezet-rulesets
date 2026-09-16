rule TTP_XOR_QUAD_CurrentVersionRun_1df2 {
  strings:
    $key_1df2 = { 4e 9d [2] 6a 93 [2] 41 bf [2] 6f 9d [2] 7b 86 [2] 74 9c [2] 6a 81 [2] 68 80 [2] 73 86 [2] 6f 81 [2] 73 ae }

  condition:
    any of them
}