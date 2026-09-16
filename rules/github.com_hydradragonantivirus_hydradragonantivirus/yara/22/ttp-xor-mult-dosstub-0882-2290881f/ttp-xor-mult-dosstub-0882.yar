rule TTP_XOR_MULT_DOSStub_0882 {
  strings:
    $key_0882 = { 5c ea [2] 28 f2 [2] 6f f0 [2] 28 e1 [2] 66 ed [2] 6a e7 [2] 7d ec [2] 66 a2 [2] 5b }

  condition:
    any of them
}