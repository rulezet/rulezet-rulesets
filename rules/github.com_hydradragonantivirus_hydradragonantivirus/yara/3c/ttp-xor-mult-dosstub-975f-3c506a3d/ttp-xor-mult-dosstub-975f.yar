rule TTP_XOR_MULT_DOSStub_975f {
  strings:
    $key_975f = { c3 37 [2] b7 2f [2] f0 2d [2] b7 3c [2] f9 30 [2] f5 3a [2] e2 31 [2] f9 7f [2] c4 }

  condition:
    any of them
}