rule TTP_XOR_MULT_DOSStub_99d6 {
  strings:
    $key_99d6 = { cd be [2] b9 a6 [2] fe a4 [2] b9 b5 [2] f7 b9 [2] fb b3 [2] ec b8 [2] f7 f6 [2] ca }

  condition:
    any of them
}