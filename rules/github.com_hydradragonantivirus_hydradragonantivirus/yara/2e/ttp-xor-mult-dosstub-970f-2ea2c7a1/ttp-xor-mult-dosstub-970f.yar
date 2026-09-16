rule TTP_XOR_MULT_DOSStub_970f {
  strings:
    $key_970f = { c3 67 [2] b7 7f [2] f0 7d [2] b7 6c [2] f9 60 [2] f5 6a [2] e2 61 [2] f9 2f [2] c4 }

  condition:
    any of them
}