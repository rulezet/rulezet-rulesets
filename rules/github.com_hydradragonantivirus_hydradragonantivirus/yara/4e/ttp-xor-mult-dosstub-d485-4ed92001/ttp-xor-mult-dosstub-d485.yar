rule TTP_XOR_MULT_DOSStub_d485 {
  strings:
    $key_d485 = { 80 ed [2] f4 f5 [2] b3 f7 [2] f4 e6 [2] ba ea [2] b6 e0 [2] a1 eb [2] ba a5 [2] 87 }

  condition:
    any of them
}