rule TTP_XOR_MULT_DOSStub_d499 {
  strings:
    $key_d499 = { 80 f1 [2] f4 e9 [2] b3 eb [2] f4 fa [2] ba f6 [2] b6 fc [2] a1 f7 [2] ba b9 [2] 87 }

  condition:
    any of them
}