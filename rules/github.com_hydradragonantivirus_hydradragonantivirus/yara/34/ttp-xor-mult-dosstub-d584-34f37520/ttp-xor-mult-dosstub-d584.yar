rule TTP_XOR_MULT_DOSStub_d584 {
  strings:
    $key_d584 = { 81 ec [2] f5 f4 [2] b2 f6 [2] f5 e7 [2] bb eb [2] b7 e1 [2] a0 ea [2] bb a4 [2] 86 }

  condition:
    any of them
}