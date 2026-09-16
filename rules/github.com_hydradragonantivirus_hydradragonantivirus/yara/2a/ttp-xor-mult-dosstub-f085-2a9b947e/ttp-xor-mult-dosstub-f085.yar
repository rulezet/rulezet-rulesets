rule TTP_XOR_MULT_DOSStub_f085 {
  strings:
    $key_f085 = { a4 ed [2] d0 f5 [2] 97 f7 [2] d0 e6 [2] 9e ea [2] 92 e0 [2] 85 eb [2] 9e a5 [2] a3 }

  condition:
    any of them
}