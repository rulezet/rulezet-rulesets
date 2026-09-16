rule TTP_XOR_QUAD_CurrentVersionRun_76e5 {
  strings:
    $key_76e5 = { 25 8a [2] 01 84 [2] 2a a8 [2] 04 8a [2] 10 91 [2] 1f 8b [2] 01 96 [2] 03 97 [2] 18 91 [2] 04 96 [2] 18 b9 }

  condition:
    any of them
}