rule TTP_XOR_QUAD_CurrentVersionRun_05a6 {
  strings:
    $key_05a6 = { 56 c9 [2] 72 c7 [2] 59 eb [2] 77 c9 [2] 63 d2 [2] 6c c8 [2] 72 d5 [2] 70 d4 [2] 6b d2 [2] 77 d5 [2] 6b fa }

  condition:
    any of them
}