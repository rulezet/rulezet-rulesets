rule TTP_XOR_QUAD_CurrentVersionRun_76e4 {
  strings:
    $key_76e4 = { 25 8b [2] 01 85 [2] 2a a9 [2] 04 8b [2] 10 90 [2] 1f 8a [2] 01 97 [2] 03 96 [2] 18 90 [2] 04 97 [2] 18 b8 }

  condition:
    any of them
}