rule TTP_XOR_MULT_DOSStub_99c3 {
  strings:
    $key_99c3 = { cd ab [2] b9 b3 [2] fe b1 [2] b9 a0 [2] f7 ac [2] fb a6 [2] ec ad [2] f7 e3 [2] ca }

  condition:
    any of them
}