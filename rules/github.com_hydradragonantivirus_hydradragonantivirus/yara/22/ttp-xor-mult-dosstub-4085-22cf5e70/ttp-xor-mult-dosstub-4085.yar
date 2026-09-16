rule TTP_XOR_MULT_DOSStub_4085 {
  strings:
    $key_4085 = { 14 ed [2] 60 f5 [2] 27 f7 [2] 60 e6 [2] 2e ea [2] 22 e0 [2] 35 eb [2] 2e a5 [2] 13 }

  condition:
    any of them
}