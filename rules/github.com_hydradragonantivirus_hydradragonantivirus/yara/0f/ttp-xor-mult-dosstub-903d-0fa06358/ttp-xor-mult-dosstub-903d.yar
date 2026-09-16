rule TTP_XOR_MULT_DOSStub_903d {
  strings:
    $key_903d = { c4 55 [2] b0 4d [2] f7 4f [2] b0 5e [2] fe 52 [2] f2 58 [2] e5 53 [2] fe 1d [2] c3 }

  condition:
    any of them
}