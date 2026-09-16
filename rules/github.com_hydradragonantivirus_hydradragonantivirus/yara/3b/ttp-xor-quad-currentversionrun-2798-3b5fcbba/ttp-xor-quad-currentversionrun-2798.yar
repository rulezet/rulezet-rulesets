rule TTP_XOR_QUAD_CurrentVersionRun_2798 {
  strings:
    $key_2798 = { 74 f7 [2] 50 f9 [2] 7b d5 [2] 55 f7 [2] 41 ec [2] 4e f6 [2] 50 eb [2] 52 ea [2] 49 ec [2] 55 eb [2] 49 c4 }

  condition:
    any of them
}