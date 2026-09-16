rule TTP_XOR_MULT_DOSStub_3085 {
  strings:
    $key_3085 = { 64 ed [2] 10 f5 [2] 57 f7 [2] 10 e6 [2] 5e ea [2] 52 e0 [2] 45 eb [2] 5e a5 [2] 63 }

  condition:
    any of them
}