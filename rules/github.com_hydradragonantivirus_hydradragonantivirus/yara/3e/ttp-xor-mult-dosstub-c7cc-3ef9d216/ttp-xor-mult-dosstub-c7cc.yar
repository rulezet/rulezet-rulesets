rule TTP_XOR_MULT_DOSStub_c7cc {
  strings:
    $key_c7cc = { 93 a4 [2] e7 bc [2] a0 be [2] e7 af [2] a9 a3 [2] a5 a9 [2] b2 a2 [2] a9 ec [2] 94 }

  condition:
    any of them
}