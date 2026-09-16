rule TTP_XOR_MULT_DOSStub_998d {
  strings:
    $key_998d = { cd e5 [2] b9 fd [2] fe ff [2] b9 ee [2] f7 e2 [2] fb e8 [2] ec e3 [2] f7 ad [2] ca }

  condition:
    any of them
}