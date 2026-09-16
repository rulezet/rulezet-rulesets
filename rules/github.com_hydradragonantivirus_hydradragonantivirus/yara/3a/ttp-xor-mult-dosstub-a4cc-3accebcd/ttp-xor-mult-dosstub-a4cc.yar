rule TTP_XOR_MULT_DOSStub_a4cc {
  strings:
    $key_a4cc = { f0 a4 [2] 84 bc [2] c3 be [2] 84 af [2] ca a3 [2] c6 a9 [2] d1 a2 [2] ca ec [2] f7 }

  condition:
    any of them
}