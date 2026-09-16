rule TTP_XOR_MULT_DOSStub_2085 {
  strings:
    $key_2085 = { 74 ed [2] 00 f5 [2] 47 f7 [2] 00 e6 [2] 4e ea [2] 42 e0 [2] 55 eb [2] 4e a5 [2] 73 }

  condition:
    any of them
}