rule TTP_XOR_MULT_DOSStub_1785 {
  strings:
    $key_1785 = { 43 ed [2] 37 f5 [2] 70 f7 [2] 37 e6 [2] 79 ea [2] 75 e0 [2] 62 eb [2] 79 a5 [2] 44 }

  condition:
    any of them
}