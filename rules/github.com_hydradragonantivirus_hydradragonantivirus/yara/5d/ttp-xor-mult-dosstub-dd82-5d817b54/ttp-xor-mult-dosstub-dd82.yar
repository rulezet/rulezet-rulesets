rule TTP_XOR_MULT_DOSStub_dd82 {
  strings:
    $key_dd82 = { 89 ea [2] fd f2 [2] ba f0 [2] fd e1 [2] b3 ed [2] bf e7 [2] a8 ec [2] b3 a2 [2] 8e }

  condition:
    any of them
}