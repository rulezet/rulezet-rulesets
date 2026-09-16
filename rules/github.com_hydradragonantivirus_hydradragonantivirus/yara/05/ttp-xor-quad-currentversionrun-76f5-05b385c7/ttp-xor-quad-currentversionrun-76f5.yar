rule TTP_XOR_QUAD_CurrentVersionRun_76f5 {
  strings:
    $key_76f5 = { 25 9a [2] 01 94 [2] 2a b8 [2] 04 9a [2] 10 81 [2] 1f 9b [2] 01 86 [2] 03 87 [2] 18 81 [2] 04 86 [2] 18 a9 }

  condition:
    any of them
}