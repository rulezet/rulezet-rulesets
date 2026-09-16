rule TTP_XOR_MULT_DOSStub_d8cc {
  strings:
    $key_d8cc = { 8c a4 [2] f8 bc [2] bf be [2] f8 af [2] b6 a3 [2] ba a9 [2] ad a2 [2] b6 ec [2] 8b }

  condition:
    any of them
}