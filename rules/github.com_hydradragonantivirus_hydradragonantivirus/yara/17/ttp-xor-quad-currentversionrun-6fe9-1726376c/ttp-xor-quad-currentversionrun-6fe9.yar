rule TTP_XOR_QUAD_CurrentVersionRun_6fe9 {
  strings:
    $key_6fe9 = { 3c 86 [2] 18 88 [2] 33 a4 [2] 1d 86 [2] 09 9d [2] 06 87 [2] 18 9a [2] 1a 9b [2] 01 9d [2] 1d 9a [2] 01 b5 }

  condition:
    any of them
}