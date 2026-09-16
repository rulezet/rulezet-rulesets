rule TTP_XOR_QUAD_CurrentVersionRun_ecf2 {
  strings:
    $key_ecf2 = { bf 9d [2] 9b 93 [2] b0 bf [2] 9e 9d [2] 8a 86 [2] 85 9c [2] 9b 81 [2] 99 80 [2] 82 86 [2] 9e 81 [2] 82 ae }

  condition:
    any of them
}