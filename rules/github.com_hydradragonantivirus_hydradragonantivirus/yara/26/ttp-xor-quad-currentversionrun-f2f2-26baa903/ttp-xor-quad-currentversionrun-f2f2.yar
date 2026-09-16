rule TTP_XOR_QUAD_CurrentVersionRun_f2f2 {
  strings:
    $key_f2f2 = { a1 9d [2] 85 93 [2] ae bf [2] 80 9d [2] 94 86 [2] 9b 9c [2] 85 81 [2] 87 80 [2] 9c 86 [2] 80 81 [2] 9c ae }

  condition:
    any of them
}