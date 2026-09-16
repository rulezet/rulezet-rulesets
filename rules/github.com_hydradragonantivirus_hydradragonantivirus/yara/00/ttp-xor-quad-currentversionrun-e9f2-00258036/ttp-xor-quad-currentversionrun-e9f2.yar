rule TTP_XOR_QUAD_CurrentVersionRun_e9f2 {
  strings:
    $key_e9f2 = { ba 9d [2] 9e 93 [2] b5 bf [2] 9b 9d [2] 8f 86 [2] 80 9c [2] 9e 81 [2] 9c 80 [2] 87 86 [2] 9b 81 [2] 87 ae }

  condition:
    any of them
}