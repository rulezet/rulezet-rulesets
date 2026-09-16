rule TTP_XOR_QUAD_CurrentVersionRun_32f2 {
  strings:
    $key_32f2 = { 61 9d [2] 45 93 [2] 6e bf [2] 40 9d [2] 54 86 [2] 5b 9c [2] 45 81 [2] 47 80 [2] 5c 86 [2] 40 81 [2] 5c ae }

  condition:
    any of them
}