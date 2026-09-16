rule TTP_XOR_MULT_DOSStub_970a {
  strings:
    $key_970a = { c3 62 [2] b7 7a [2] f0 78 [2] b7 69 [2] f9 65 [2] f5 6f [2] e2 64 [2] f9 2a [2] c4 }

  condition:
    any of them
}