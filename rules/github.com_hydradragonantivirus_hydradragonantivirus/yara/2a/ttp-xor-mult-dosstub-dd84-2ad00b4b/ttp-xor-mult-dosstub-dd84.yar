rule TTP_XOR_MULT_DOSStub_dd84 {
  strings:
    $key_dd84 = { 89 ec [2] fd f4 [2] ba f6 [2] fd e7 [2] b3 eb [2] bf e1 [2] a8 ea [2] b3 a4 [2] 8e }

  condition:
    any of them
}