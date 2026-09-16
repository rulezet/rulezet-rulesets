rule TTP_XOR_MULT_DOSStub_963f {
  strings:
    $key_963f = { c2 57 [2] b6 4f [2] f1 4d [2] b6 5c [2] f8 50 [2] f4 5a [2] e3 51 [2] f8 1f [2] c5 }

  condition:
    any of them
}