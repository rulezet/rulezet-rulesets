rule TTP_XOR_MULT_DOSStub_99d9 {
  strings:
    $key_99d9 = { cd b1 [2] b9 a9 [2] fe ab [2] b9 ba [2] f7 b6 [2] fb bc [2] ec b7 [2] f7 f9 [2] ca }

  condition:
    any of them
}