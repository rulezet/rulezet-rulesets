rule TTP_XOR_MULT_DOSStub_83cb {
  strings:
    $key_83cb = { d7 a3 [2] a3 bb [2] e4 b9 [2] a3 a8 [2] ed a4 [2] e1 ae [2] f6 a5 [2] ed eb [2] d0 }

  condition:
    any of them
}