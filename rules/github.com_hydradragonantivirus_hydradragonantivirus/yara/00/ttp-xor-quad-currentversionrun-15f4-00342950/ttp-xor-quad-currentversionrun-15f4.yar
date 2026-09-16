rule TTP_XOR_QUAD_CurrentVersionRun_15f4 {
  strings:
    $key_15f4 = { 46 9b [2] 62 95 [2] 49 b9 [2] 67 9b [2] 73 80 [2] 7c 9a [2] 62 87 [2] 60 86 [2] 7b 80 [2] 67 87 [2] 7b a8 }

  condition:
    any of them
}