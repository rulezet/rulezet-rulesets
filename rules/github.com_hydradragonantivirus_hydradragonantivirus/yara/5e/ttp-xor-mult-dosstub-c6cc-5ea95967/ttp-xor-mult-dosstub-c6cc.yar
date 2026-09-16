rule TTP_XOR_MULT_DOSStub_c6cc {
  strings:
    $key_c6cc = { 92 a4 [2] e6 bc [2] a1 be [2] e6 af [2] a8 a3 [2] a4 a9 [2] b3 a2 [2] a8 ec [2] 95 }

  condition:
    any of them
}