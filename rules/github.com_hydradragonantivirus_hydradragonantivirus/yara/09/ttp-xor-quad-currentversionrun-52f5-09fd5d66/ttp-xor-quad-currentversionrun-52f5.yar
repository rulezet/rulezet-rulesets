rule TTP_XOR_QUAD_CurrentVersionRun_52f5 {
  strings:
    $key_52f5 = { 01 9a [2] 25 94 [2] 0e b8 [2] 20 9a [2] 34 81 [2] 3b 9b [2] 25 86 [2] 27 87 [2] 3c 81 [2] 20 86 [2] 3c a9 }

  condition:
    any of them
}