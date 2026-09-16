rule TTP_XOR_QUAD_CurrentVersionRun_65e8 {
  strings:
    $key_65e8 = { 36 87 [2] 12 89 [2] 39 a5 [2] 17 87 [2] 03 9c [2] 0c 86 [2] 12 9b [2] 10 9a [2] 0b 9c [2] 17 9b [2] 0b b4 }

  condition:
    any of them
}