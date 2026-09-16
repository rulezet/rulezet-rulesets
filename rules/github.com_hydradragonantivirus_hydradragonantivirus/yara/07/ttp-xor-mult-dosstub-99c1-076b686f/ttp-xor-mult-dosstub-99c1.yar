rule TTP_XOR_MULT_DOSStub_99c1 {
  strings:
    $key_99c1 = { cd a9 [2] b9 b1 [2] fe b3 [2] b9 a2 [2] f7 ae [2] fb a4 [2] ec af [2] f7 e1 [2] ca }

  condition:
    any of them
}