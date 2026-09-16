rule TTP_XOR_MULT_DOSStub_96cb {
  strings:
    $key_96cb = { c2 a3 [2] b6 bb [2] f1 b9 [2] b6 a8 [2] f8 a4 [2] f4 ae [2] e3 a5 [2] f8 eb [2] c5 }

  condition:
    any of them
}