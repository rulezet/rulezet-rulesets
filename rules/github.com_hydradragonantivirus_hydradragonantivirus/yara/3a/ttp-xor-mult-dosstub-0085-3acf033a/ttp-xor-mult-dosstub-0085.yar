rule TTP_XOR_MULT_DOSStub_0085 {
  strings:
    $key_0085 = { 54 ed [2] 20 f5 [2] 67 f7 [2] 20 e6 [2] 6e ea [2] 62 e0 [2] 75 eb [2] 6e a5 [2] 53 }

  condition:
    any of them
}