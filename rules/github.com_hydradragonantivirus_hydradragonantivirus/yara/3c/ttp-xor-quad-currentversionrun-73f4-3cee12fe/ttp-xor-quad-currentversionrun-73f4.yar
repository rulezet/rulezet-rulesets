rule TTP_XOR_QUAD_CurrentVersionRun_73f4 {
  strings:
    $key_73f4 = { 20 9b [2] 04 95 [2] 2f b9 [2] 01 9b [2] 15 80 [2] 1a 9a [2] 04 87 [2] 06 86 [2] 1d 80 [2] 01 87 [2] 1d a8 }

  condition:
    any of them
}