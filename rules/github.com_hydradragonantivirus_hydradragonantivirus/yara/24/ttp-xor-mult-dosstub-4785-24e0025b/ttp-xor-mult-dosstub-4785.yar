rule TTP_XOR_MULT_DOSStub_4785 {
  strings:
    $key_4785 = { 13 ed [2] 67 f5 [2] 20 f7 [2] 67 e6 [2] 29 ea [2] 25 e0 [2] 32 eb [2] 29 a5 [2] 14 }

  condition:
    any of them
}