rule TTP_XOR_MULT_DOSStub_84cc {
  strings:
    $key_84cc = { d0 a4 [2] a4 bc [2] e3 be [2] a4 af [2] ea a3 [2] e6 a9 [2] f1 a2 [2] ea ec [2] d7 }

  condition:
    any of them
}