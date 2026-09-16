rule TTP_XOR_MULT_DOSStub_902a {
  strings:
    $key_902a = { c4 42 [2] b0 5a [2] f7 58 [2] b0 49 [2] fe 45 [2] f2 4f [2] e5 44 [2] fe 0a [2] c3 }

  condition:
    any of them
}