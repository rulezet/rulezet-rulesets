rule TTP_XOR_MULT_DOSStub_99d4 {
  strings:
    $key_99d4 = { cd bc [2] b9 a4 [2] fe a6 [2] b9 b7 [2] f7 bb [2] fb b1 [2] ec ba [2] f7 f4 [2] ca }

  condition:
    any of them
}