rule TTP_XOR_MULT_DOSStub_819c {
  strings:
    $key_819c = { d5 f4 [2] a1 ec [2] e6 ee [2] a1 ff [2] ef f3 [2] e3 f9 [2] f4 f2 [2] ef bc [2] d2 }

  condition:
    any of them
}