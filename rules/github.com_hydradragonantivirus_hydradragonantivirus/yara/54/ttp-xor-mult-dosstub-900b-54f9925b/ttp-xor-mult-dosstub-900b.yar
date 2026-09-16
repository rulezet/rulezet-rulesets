rule TTP_XOR_MULT_DOSStub_900b {
  strings:
    $key_900b = { c4 63 [2] b0 7b [2] f7 79 [2] b0 68 [2] fe 64 [2] f2 6e [2] e5 65 [2] fe 2b [2] c3 }

  condition:
    any of them
}