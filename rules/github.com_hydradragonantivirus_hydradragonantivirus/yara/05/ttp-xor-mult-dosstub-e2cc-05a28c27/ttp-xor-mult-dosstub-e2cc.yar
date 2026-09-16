rule TTP_XOR_MULT_DOSStub_e2cc {
  strings:
    $key_e2cc = { b6 a4 [2] c2 bc [2] 85 be [2] c2 af [2] 8c a3 [2] 80 a9 [2] 97 a2 [2] 8c ec [2] b1 }

  condition:
    any of them
}