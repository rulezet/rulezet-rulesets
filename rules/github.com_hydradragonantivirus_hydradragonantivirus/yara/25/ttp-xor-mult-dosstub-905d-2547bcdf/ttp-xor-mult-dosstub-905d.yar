rule TTP_XOR_MULT_DOSStub_905d {
  strings:
    $key_905d = { c4 35 [2] b0 2d [2] f7 2f [2] b0 3e [2] fe 32 [2] f2 38 [2] e5 33 [2] fe 7d [2] c3 }

  condition:
    any of them
}