rule TTP_XOR_MULT_DOSStub_f283 {
  strings:
    $key_f283 = { a6 eb [2] d2 f3 [2] 95 f1 [2] d2 e0 [2] 9c ec [2] 90 e6 [2] 87 ed [2] 9c a3 [2] a1 }

  condition:
    any of them
}