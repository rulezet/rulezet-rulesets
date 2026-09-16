rule TTP_XOR_MULT_DOSStub_907a {
  strings:
    $key_907a = { c4 12 [2] b0 0a [2] f7 08 [2] b0 19 [2] fe 15 [2] f2 1f [2] e5 14 [2] fe 5a [2] c3 }

  condition:
    any of them
}