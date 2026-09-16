rule TTP_XOR_MULT_DOSStub_a085 {
  strings:
    $key_a085 = { f4 ed [2] 80 f5 [2] c7 f7 [2] 80 e6 [2] ce ea [2] c2 e0 [2] d5 eb [2] ce a5 [2] f3 }

  condition:
    any of them
}