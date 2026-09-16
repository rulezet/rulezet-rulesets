rule TTP_XOR_QUAD_CurrentVersionRun_12f2 {
  strings:
    $key_12f2 = { 41 9d [2] 65 93 [2] 4e bf [2] 60 9d [2] 74 86 [2] 7b 9c [2] 65 81 [2] 67 80 [2] 7c 86 [2] 60 81 [2] 7c ae }

  condition:
    any of them
}