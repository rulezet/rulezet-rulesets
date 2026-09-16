rule TTP_XOR_QUAD_CurrentVersionRun_0785 {
  strings:
    $key_0785 = { 54 ea [2] 70 e4 [2] 5b c8 [2] 75 ea [2] 61 f1 [2] 6e eb [2] 70 f6 [2] 72 f7 [2] 69 f1 [2] 75 f6 [2] 69 d9 }

  condition:
    any of them
}