rule TTP_XOR_QUAD_CurrentVersionRun_1cf2 {
  strings:
    $key_1cf2 = { 4f 9d [2] 6b 93 [2] 40 bf [2] 6e 9d [2] 7a 86 [2] 75 9c [2] 6b 81 [2] 69 80 [2] 72 86 [2] 6e 81 [2] 72 ae }

  condition:
    any of them
}