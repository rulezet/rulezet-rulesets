rule TTP_XOR_MULT_DOSStub_929c {
  strings:
    $key_929c = { c6 f4 [2] b2 ec [2] f5 ee [2] b2 ff [2] fc f3 [2] f0 f9 [2] e7 f2 [2] fc bc [2] c1 }

  condition:
    any of them
}