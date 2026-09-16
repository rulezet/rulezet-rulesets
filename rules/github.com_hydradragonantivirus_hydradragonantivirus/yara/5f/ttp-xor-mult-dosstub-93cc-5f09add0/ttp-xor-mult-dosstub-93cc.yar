rule TTP_XOR_MULT_DOSStub_93cc {
  strings:
    $key_93cc = { c7 a4 [2] b3 bc [2] f4 be [2] b3 af [2] fd a3 [2] f1 a9 [2] e6 a2 [2] fd ec [2] c0 }

  condition:
    any of them
}