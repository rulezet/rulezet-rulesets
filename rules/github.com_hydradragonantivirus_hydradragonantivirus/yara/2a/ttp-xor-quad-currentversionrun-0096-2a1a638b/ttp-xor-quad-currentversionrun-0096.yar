rule TTP_XOR_QUAD_CurrentVersionRun_0096 {
  strings:
    $key_0096 = { 53 f9 [2] 77 f7 [2] 5c db [2] 72 f9 [2] 66 e2 [2] 69 f8 [2] 77 e5 [2] 75 e4 [2] 6e e2 [2] 72 e5 [2] 6e ca }

  condition:
    any of them
}