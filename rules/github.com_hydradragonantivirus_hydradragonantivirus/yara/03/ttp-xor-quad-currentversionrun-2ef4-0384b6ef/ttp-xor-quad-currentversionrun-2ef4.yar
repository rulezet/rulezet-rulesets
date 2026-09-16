rule TTP_XOR_QUAD_CurrentVersionRun_2ef4 {
  strings:
    $key_2ef4 = { 7d 9b [2] 59 95 [2] 72 b9 [2] 5c 9b [2] 48 80 [2] 47 9a [2] 59 87 [2] 5b 86 [2] 40 80 [2] 5c 87 [2] 40 a8 }

  condition:
    any of them
}