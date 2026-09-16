rule TTP_XOR_QUAD_CurrentVersionRun_55f4 {
  strings:
    $key_55f4 = { 06 9b [2] 22 95 [2] 09 b9 [2] 27 9b [2] 33 80 [2] 3c 9a [2] 22 87 [2] 20 86 [2] 3b 80 [2] 27 87 [2] 3b a8 }

  condition:
    any of them
}