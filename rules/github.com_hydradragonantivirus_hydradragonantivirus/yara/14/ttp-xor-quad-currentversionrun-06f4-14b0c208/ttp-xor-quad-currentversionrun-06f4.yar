rule TTP_XOR_QUAD_CurrentVersionRun_06f4 {
  strings:
    $key_06f4 = { 55 9b [2] 71 95 [2] 5a b9 [2] 74 9b [2] 60 80 [2] 6f 9a [2] 71 87 [2] 73 86 [2] 68 80 [2] 74 87 [2] 68 a8 }

  condition:
    any of them
}