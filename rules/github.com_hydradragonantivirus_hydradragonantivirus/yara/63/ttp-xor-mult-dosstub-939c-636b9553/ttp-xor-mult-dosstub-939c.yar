rule TTP_XOR_MULT_DOSStub_939c {
  strings:
    $key_939c = { c7 f4 [2] b3 ec [2] f4 ee [2] b3 ff [2] fd f3 [2] f1 f9 [2] e6 f2 [2] fd bc [2] c0 }

  condition:
    any of them
}