rule TTP_XOR_QUAD_CurrentVersionRun_3785 {
  strings:
    $key_3785 = { 64 ea [2] 40 e4 [2] 6b c8 [2] 45 ea [2] 51 f1 [2] 5e eb [2] 40 f6 [2] 42 f7 [2] 59 f1 [2] 45 f6 [2] 59 d9 }

  condition:
    any of them
}