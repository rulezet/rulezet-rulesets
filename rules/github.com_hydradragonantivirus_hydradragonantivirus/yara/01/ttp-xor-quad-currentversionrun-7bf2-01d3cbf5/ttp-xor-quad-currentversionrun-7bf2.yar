rule TTP_XOR_QUAD_CurrentVersionRun_7bf2 {
  strings:
    $key_7bf2 = { 28 9d [2] 0c 93 [2] 27 bf [2] 09 9d [2] 1d 86 [2] 12 9c [2] 0c 81 [2] 0e 80 [2] 15 86 [2] 09 81 [2] 15 ae }

  condition:
    any of them
}