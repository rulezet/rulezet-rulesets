rule TTP_XOR_QUAD_CurrentVersionRun_05c6 {
  strings:
    $key_05c6 = { 56 a9 [2] 72 a7 [2] 59 8b [2] 77 a9 [2] 63 b2 [2] 6c a8 [2] 72 b5 [2] 70 b4 [2] 6b b2 [2] 77 b5 [2] 6b 9a }

  condition:
    any of them
}