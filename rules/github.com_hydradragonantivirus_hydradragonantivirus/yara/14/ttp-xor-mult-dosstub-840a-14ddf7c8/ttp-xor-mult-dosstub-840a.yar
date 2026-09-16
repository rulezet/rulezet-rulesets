rule TTP_XOR_MULT_DOSStub_840a {
  strings:
    $key_840a = { d0 62 [2] a4 7a [2] e3 78 [2] a4 69 [2] ea 65 [2] e6 6f [2] f1 64 [2] ea 2a [2] d7 }

  condition:
    any of them
}