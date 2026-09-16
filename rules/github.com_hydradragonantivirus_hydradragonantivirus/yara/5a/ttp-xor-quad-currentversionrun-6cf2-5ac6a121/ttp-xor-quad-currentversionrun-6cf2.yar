rule TTP_XOR_QUAD_CurrentVersionRun_6cf2 {
  strings:
    $key_6cf2 = { 3f 9d [2] 1b 93 [2] 30 bf [2] 1e 9d [2] 0a 86 [2] 05 9c [2] 1b 81 [2] 19 80 [2] 02 86 [2] 1e 81 [2] 02 ae }

  condition:
    any of them
}