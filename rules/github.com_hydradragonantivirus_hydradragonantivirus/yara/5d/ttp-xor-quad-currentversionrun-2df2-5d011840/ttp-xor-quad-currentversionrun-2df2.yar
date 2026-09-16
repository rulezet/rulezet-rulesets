rule TTP_XOR_QUAD_CurrentVersionRun_2df2 {
  strings:
    $key_2df2 = { 7e 9d [2] 5a 93 [2] 71 bf [2] 5f 9d [2] 4b 86 [2] 44 9c [2] 5a 81 [2] 58 80 [2] 43 86 [2] 5f 81 [2] 43 ae }

  condition:
    any of them
}