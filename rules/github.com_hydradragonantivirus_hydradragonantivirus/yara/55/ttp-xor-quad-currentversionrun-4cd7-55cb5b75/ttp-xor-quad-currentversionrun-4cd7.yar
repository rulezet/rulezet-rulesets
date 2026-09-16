rule TTP_XOR_QUAD_CurrentVersionRun_4cd7 {
  strings:
    $key_4cd7 = { 1f b8 [2] 3b b6 [2] 10 9a [2] 3e b8 [2] 2a a3 [2] 25 b9 [2] 3b a4 [2] 39 a5 [2] 22 a3 [2] 3e a4 [2] 22 8b }

  condition:
    any of them
}