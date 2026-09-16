rule TTP_XOR_MULT_DOSStub_99b7 {
  strings:
    $key_99b7 = { cd df [2] b9 c7 [2] fe c5 [2] b9 d4 [2] f7 d8 [2] fb d2 [2] ec d9 [2] f7 97 [2] ca }

  condition:
    any of them
}