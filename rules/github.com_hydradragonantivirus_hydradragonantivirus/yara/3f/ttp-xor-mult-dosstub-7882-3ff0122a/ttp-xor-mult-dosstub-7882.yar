rule TTP_XOR_MULT_DOSStub_7882 {
  strings:
    $key_7882 = { 2c ea [2] 58 f2 [2] 1f f0 [2] 58 e1 [2] 16 ed [2] 1a e7 [2] 0d ec [2] 16 a2 [2] 2b }

  condition:
    any of them
}