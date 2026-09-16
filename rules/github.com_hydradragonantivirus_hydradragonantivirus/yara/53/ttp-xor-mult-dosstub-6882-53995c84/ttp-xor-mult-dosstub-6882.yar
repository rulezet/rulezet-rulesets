rule TTP_XOR_MULT_DOSStub_6882 {
  strings:
    $key_6882 = { 3c ea [2] 48 f2 [2] 0f f0 [2] 48 e1 [2] 06 ed [2] 0a e7 [2] 1d ec [2] 06 a2 [2] 3b }

  condition:
    any of them
}