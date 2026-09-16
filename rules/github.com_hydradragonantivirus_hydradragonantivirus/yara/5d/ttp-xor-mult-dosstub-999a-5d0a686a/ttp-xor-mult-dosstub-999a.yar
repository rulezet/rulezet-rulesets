rule TTP_XOR_MULT_DOSStub_999a {
  strings:
    $key_999a = { cd f2 [2] b9 ea [2] fe e8 [2] b9 f9 [2] f7 f5 [2] fb ff [2] ec f4 [2] f7 ba [2] ca }

  condition:
    any of them
}