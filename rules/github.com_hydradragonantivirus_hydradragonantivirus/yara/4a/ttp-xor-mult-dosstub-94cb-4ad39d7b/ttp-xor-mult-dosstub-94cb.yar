rule TTP_XOR_MULT_DOSStub_94cb {
  strings:
    $key_94cb = { c0 a3 [2] b4 bb [2] f3 b9 [2] b4 a8 [2] fa a4 [2] f6 ae [2] e1 a5 [2] fa eb [2] c7 }

  condition:
    any of them
}