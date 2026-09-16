rule TTP_XOR_QUAD_CurrentVersionRun_4cf4 {
  strings:
    $key_4cf4 = { 1f 9b [2] 3b 95 [2] 10 b9 [2] 3e 9b [2] 2a 80 [2] 25 9a [2] 3b 87 [2] 39 86 [2] 22 80 [2] 3e 87 [2] 22 a8 }

  condition:
    any of them
}