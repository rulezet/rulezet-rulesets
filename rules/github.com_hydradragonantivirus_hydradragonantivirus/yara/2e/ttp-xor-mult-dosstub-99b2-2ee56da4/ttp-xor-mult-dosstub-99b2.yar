rule TTP_XOR_MULT_DOSStub_99b2 {
  strings:
    $key_99b2 = { cd da [2] b9 c2 [2] fe c0 [2] b9 d1 [2] f7 dd [2] fb d7 [2] ec dc [2] f7 92 [2] ca }

  condition:
    any of them
}