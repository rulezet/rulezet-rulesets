rule TTP_XOR_MULT_DOSStub_0785 {
  strings:
    $key_0785 = { 53 ed [2] 27 f5 [2] 60 f7 [2] 27 e6 [2] 69 ea [2] 65 e0 [2] 72 eb [2] 69 a5 [2] 54 }

  condition:
    any of them
}