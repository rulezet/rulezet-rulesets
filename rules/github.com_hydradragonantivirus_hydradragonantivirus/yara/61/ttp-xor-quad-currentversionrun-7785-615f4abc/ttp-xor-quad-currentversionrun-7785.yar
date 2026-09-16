rule TTP_XOR_QUAD_CurrentVersionRun_7785 {
  strings:
    $key_7785 = { 24 ea [2] 00 e4 [2] 2b c8 [2] 05 ea [2] 11 f1 [2] 1e eb [2] 00 f6 [2] 02 f7 [2] 19 f1 [2] 05 f6 [2] 19 d9 }

  condition:
    any of them
}