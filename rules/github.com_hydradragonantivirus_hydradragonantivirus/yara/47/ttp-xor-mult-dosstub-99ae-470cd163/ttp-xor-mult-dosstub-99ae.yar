rule TTP_XOR_MULT_DOSStub_99ae {
  strings:
    $key_99ae = { cd c6 [2] b9 de [2] fe dc [2] b9 cd [2] f7 c1 [2] fb cb [2] ec c0 [2] f7 8e [2] ca }

  condition:
    any of them
}