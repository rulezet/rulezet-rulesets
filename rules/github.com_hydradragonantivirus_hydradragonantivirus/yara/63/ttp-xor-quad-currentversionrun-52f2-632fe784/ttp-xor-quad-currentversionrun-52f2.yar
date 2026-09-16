rule TTP_XOR_QUAD_CurrentVersionRun_52f2 {
  strings:
    $key_52f2 = { 01 9d [2] 25 93 [2] 0e bf [2] 20 9d [2] 34 86 [2] 3b 9c [2] 25 81 [2] 27 80 [2] 3c 86 [2] 20 81 [2] 3c ae }

  condition:
    any of them
}