rule TTP_XOR_QUAD_CurrentVersionRun_e5f2 {
  strings:
    $key_e5f2 = { b6 9d [2] 92 93 [2] b9 bf [2] 97 9d [2] 83 86 [2] 8c 9c [2] 92 81 [2] 90 80 [2] 8b 86 [2] 97 81 [2] 8b ae }

  condition:
    any of them
}