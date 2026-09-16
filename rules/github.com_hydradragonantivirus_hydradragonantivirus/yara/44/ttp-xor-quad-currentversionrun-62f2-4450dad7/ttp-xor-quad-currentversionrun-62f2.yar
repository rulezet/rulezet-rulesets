rule TTP_XOR_QUAD_CurrentVersionRun_62f2 {
  strings:
    $key_62f2 = { 31 9d [2] 15 93 [2] 3e bf [2] 10 9d [2] 04 86 [2] 0b 9c [2] 15 81 [2] 17 80 [2] 0c 86 [2] 10 81 [2] 0c ae }

  condition:
    any of them
}