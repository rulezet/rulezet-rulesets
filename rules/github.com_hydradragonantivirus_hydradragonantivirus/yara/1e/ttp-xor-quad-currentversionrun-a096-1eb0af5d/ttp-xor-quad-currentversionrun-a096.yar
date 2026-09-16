rule TTP_XOR_QUAD_CurrentVersionRun_a096 {
  strings:
    $key_a096 = { f3 f9 [2] d7 f7 [2] fc db [2] d2 f9 [2] c6 e2 [2] c9 f8 [2] d7 e5 [2] d5 e4 [2] ce e2 [2] d2 e5 [2] ce ca }

  condition:
    any of them
}