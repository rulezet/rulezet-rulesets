rule TTP_XOR_MULT_DOSStub_8184 {
  strings:
    $key_8184 = { d5 ec [2] a1 f4 [2] e6 f6 [2] a1 e7 [2] ef eb [2] e3 e1 [2] f4 ea [2] ef a4 [2] d2 }

  condition:
    any of them
}