rule TTP_XOR_MULT_DOSStub_99b1 {
  strings:
    $key_99b1 = { cd d9 [2] b9 c1 [2] fe c3 [2] b9 d2 [2] f7 de [2] fb d4 [2] ec df [2] f7 91 [2] ca }

  condition:
    any of them
}