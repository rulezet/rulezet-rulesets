rule TTP_XOR_MULT_DOSStub_c1cc {
  strings:
    $key_c1cc = { 95 a4 [2] e1 bc [2] a6 be [2] e1 af [2] af a3 [2] a3 a9 [2] b4 a2 [2] af ec [2] 92 }

  condition:
    any of them
}