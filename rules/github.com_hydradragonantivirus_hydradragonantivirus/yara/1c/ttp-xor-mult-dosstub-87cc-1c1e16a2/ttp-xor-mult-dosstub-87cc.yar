rule TTP_XOR_MULT_DOSStub_87cc {
  strings:
    $key_87cc = { d3 a4 [2] a7 bc [2] e0 be [2] a7 af [2] e9 a3 [2] e5 a9 [2] f2 a2 [2] e9 ec [2] d4 }

  condition:
    any of them
}