rule TTP_XOR_QUAD_CurrentVersionRun_58f2 {
  strings:
    $key_58f2 = { 0b 9d [2] 2f 93 [2] 04 bf [2] 2a 9d [2] 3e 86 [2] 31 9c [2] 2f 81 [2] 2d 80 [2] 36 86 [2] 2a 81 [2] 36 ae }

  condition:
    any of them
}