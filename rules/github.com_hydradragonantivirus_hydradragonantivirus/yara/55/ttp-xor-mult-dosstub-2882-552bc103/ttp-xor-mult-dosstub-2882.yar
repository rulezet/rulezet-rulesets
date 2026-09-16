rule TTP_XOR_MULT_DOSStub_2882 {
  strings:
    $key_2882 = { 7c ea [2] 08 f2 [2] 4f f0 [2] 08 e1 [2] 46 ed [2] 4a e7 [2] 5d ec [2] 46 a2 [2] 7b }

  condition:
    any of them
}