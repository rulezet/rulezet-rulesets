rule TTP_XOR_MULT_DOSStub_e6cc {
  strings:
    $key_e6cc = { b2 a4 [2] c6 bc [2] 81 be [2] c6 af [2] 88 a3 [2] 84 a9 [2] 93 a2 [2] 88 ec [2] b5 }

  condition:
    any of them
}