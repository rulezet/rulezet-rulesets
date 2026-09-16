rule TTP_XOR_MULT_DOSStub_99c6 {
  strings:
    $key_99c6 = { cd ae [2] b9 b6 [2] fe b4 [2] b9 a5 [2] f7 a9 [2] fb a3 [2] ec a8 [2] f7 e6 [2] ca }

  condition:
    any of them
}