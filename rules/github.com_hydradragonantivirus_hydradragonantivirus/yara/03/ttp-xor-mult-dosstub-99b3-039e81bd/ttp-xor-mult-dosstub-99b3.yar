rule TTP_XOR_MULT_DOSStub_99b3 {
  strings:
    $key_99b3 = { cd db [2] b9 c3 [2] fe c1 [2] b9 d0 [2] f7 dc [2] fb d6 [2] ec dd [2] f7 93 [2] ca }

  condition:
    any of them
}