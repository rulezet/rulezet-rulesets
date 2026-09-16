rule TTP_XOR_QUAD_CurrentVersionRun_55e8 {
  strings:
    $key_55e8 = { 06 87 [2] 22 89 [2] 09 a5 [2] 27 87 [2] 33 9c [2] 3c 86 [2] 22 9b [2] 20 9a [2] 3b 9c [2] 27 9b [2] 3b b4 }

  condition:
    any of them
}