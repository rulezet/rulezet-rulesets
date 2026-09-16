rule TTP_XOR_MULT_DOSStub_91a3 {
  strings:
    $key_91a3 = { c5 cb [2] b1 d3 [2] f6 d1 [2] b1 c0 [2] ff cc [2] f3 c6 [2] e4 cd [2] ff 83 [2] c2 }

  condition:
    any of them
}