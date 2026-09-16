rule TTP_XOR_MULT_DOSStub_998b {
  strings:
    $key_998b = { cd e3 [2] b9 fb [2] fe f9 [2] b9 e8 [2] f7 e4 [2] fb ee [2] ec e5 [2] f7 ab [2] ca }

  condition:
    any of them
}