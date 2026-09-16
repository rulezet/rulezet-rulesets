rule TTP_XOR_MULT_DOSStub_d7cc {
  strings:
    $key_d7cc = { 83 a4 [2] f7 bc [2] b0 be [2] f7 af [2] b9 a3 [2] b5 a9 [2] a2 a2 [2] b9 ec [2] 84 }

  condition:
    any of them
}