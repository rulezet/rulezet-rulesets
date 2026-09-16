rule TTP_XOR_QUAD_CurrentVersionRun_7ef4 {
  strings:
    $key_7ef4 = { 2d 9b [2] 09 95 [2] 22 b9 [2] 0c 9b [2] 18 80 [2] 17 9a [2] 09 87 [2] 0b 86 [2] 10 80 [2] 0c 87 [2] 10 a8 }

  condition:
    any of them
}