rule TTP_XOR_MULT_DOSStub_d783 {
  strings:
    $key_d783 = { 83 eb [2] f7 f3 [2] b0 f1 [2] f7 e0 [2] b9 ec [2] b5 e6 [2] a2 ed [2] b9 a3 [2] 84 }

  condition:
    any of them
}