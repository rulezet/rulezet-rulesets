rule TTP_XOR_MULT_DOSStub_99b0 {
  strings:
    $key_99b0 = { cd d8 [2] b9 c0 [2] fe c2 [2] b9 d3 [2] f7 df [2] fb d5 [2] ec de [2] f7 90 [2] ca }

  condition:
    any of them
}