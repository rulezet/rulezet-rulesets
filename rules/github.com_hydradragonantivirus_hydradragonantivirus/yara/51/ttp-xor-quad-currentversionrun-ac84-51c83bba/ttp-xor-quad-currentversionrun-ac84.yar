rule TTP_XOR_QUAD_CurrentVersionRun_ac84 {
  strings:
    $key_ac84 = { ff eb [2] db e5 [2] f0 c9 [2] de eb [2] ca f0 [2] c5 ea [2] db f7 [2] d9 f6 [2] c2 f0 [2] de f7 [2] c2 d8 }

  condition:
    any of them
}