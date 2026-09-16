rule TTP_XOR_MULT_DOSStub_99ce {
  strings:
    $key_99ce = { cd a6 [2] b9 be [2] fe bc [2] b9 ad [2] f7 a1 [2] fb ab [2] ec a0 [2] f7 ee [2] ca }

  condition:
    any of them
}