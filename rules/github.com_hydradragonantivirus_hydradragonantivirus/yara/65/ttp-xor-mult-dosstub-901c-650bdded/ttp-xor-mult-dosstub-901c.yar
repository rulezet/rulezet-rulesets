rule TTP_XOR_MULT_DOSStub_901c {
  strings:
    $key_901c = { c4 74 [2] b0 6c [2] f7 6e [2] b0 7f [2] fe 73 [2] f2 79 [2] e5 72 [2] fe 3c [2] c3 }

  condition:
    any of them
}