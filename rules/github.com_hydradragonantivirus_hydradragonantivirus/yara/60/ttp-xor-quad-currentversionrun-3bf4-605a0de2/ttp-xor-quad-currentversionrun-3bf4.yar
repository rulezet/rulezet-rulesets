rule TTP_XOR_QUAD_CurrentVersionRun_3bf4 {
  strings:
    $key_3bf4 = { 68 9b [2] 4c 95 [2] 67 b9 [2] 49 9b [2] 5d 80 [2] 52 9a [2] 4c 87 [2] 4e 86 [2] 55 80 [2] 49 87 [2] 55 a8 }

  condition:
    any of them
}