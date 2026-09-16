rule TTP_XOR_QUAD_CurrentVersionRun_56e5 {
  strings:
    $key_56e5 = { 05 8a [2] 21 84 [2] 0a a8 [2] 24 8a [2] 30 91 [2] 3f 8b [2] 21 96 [2] 23 97 [2] 38 91 [2] 24 96 [2] 38 b9 }

  condition:
    any of them
}