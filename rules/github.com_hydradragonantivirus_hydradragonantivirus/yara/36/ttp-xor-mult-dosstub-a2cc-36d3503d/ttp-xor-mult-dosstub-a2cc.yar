rule TTP_XOR_MULT_DOSStub_a2cc {
  strings:
    $key_a2cc = { f6 a4 [2] 82 bc [2] c5 be [2] 82 af [2] cc a3 [2] c0 a9 [2] d7 a2 [2] cc ec [2] f1 }

  condition:
    any of them
}