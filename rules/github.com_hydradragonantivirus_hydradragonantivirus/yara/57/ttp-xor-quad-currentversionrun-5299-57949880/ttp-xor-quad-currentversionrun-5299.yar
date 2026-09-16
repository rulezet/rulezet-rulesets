rule TTP_XOR_QUAD_CurrentVersionRun_5299 {
  strings:
    $key_5299 = { 01 f6 [2] 25 f8 [2] 0e d4 [2] 20 f6 [2] 34 ed [2] 3b f7 [2] 25 ea [2] 27 eb [2] 3c ed [2] 20 ea [2] 3c c5 }

  condition:
    any of them
}