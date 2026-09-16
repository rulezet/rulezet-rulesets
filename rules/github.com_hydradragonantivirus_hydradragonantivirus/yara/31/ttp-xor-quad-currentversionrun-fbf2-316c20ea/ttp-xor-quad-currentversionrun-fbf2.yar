rule TTP_XOR_QUAD_CurrentVersionRun_fbf2 {
  strings:
    $key_fbf2 = { a8 9d [2] 8c 93 [2] a7 bf [2] 89 9d [2] 9d 86 [2] 92 9c [2] 8c 81 [2] 8e 80 [2] 95 86 [2] 89 81 [2] 95 ae }

  condition:
    any of them
}