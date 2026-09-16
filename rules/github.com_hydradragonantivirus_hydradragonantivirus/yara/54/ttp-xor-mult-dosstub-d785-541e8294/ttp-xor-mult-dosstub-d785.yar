rule TTP_XOR_MULT_DOSStub_d785 {
  strings:
    $key_d785 = { 83 ed [2] f7 f5 [2] b0 f7 [2] f7 e6 [2] b9 ea [2] b5 e0 [2] a2 eb [2] b9 a5 [2] 84 }

  condition:
    any of them
}