rule TTP_XOR_QUAD_CurrentVersionRun_4bf4 {
  strings:
    $key_4bf4 = { 18 9b [2] 3c 95 [2] 17 b9 [2] 39 9b [2] 2d 80 [2] 22 9a [2] 3c 87 [2] 3e 86 [2] 25 80 [2] 39 87 [2] 25 a8 }

  condition:
    any of them
}