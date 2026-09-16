rule TTP_XOR_QUAD_CurrentVersionRun_7cf2 {
  strings:
    $key_7cf2 = { 2f 9d [2] 0b 93 [2] 20 bf [2] 0e 9d [2] 1a 86 [2] 15 9c [2] 0b 81 [2] 09 80 [2] 12 86 [2] 0e 81 [2] 12 ae }

  condition:
    any of them
}