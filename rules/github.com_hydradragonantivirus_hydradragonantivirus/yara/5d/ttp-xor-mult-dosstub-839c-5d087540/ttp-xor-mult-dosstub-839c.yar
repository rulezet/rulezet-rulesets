rule TTP_XOR_MULT_DOSStub_839c {
  strings:
    $key_839c = { d7 f4 [2] a3 ec [2] e4 ee [2] a3 ff [2] ed f3 [2] e1 f9 [2] f6 f2 [2] ed bc [2] d0 }

  condition:
    any of them
}