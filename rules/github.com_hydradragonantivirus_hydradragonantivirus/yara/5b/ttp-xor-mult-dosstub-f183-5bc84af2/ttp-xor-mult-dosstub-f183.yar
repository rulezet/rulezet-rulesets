rule TTP_XOR_MULT_DOSStub_f183 {
  strings:
    $key_f183 = { a5 eb [2] d1 f3 [2] 96 f1 [2] d1 e0 [2] 9f ec [2] 93 e6 [2] 84 ed [2] 9f a3 [2] a2 }

  condition:
    any of them
}