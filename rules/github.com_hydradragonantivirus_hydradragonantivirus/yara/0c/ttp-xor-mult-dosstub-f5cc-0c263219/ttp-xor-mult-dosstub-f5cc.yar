rule TTP_XOR_MULT_DOSStub_f5cc {
  strings:
    $key_f5cc = { a1 a4 [2] d5 bc [2] 92 be [2] d5 af [2] 9b a3 [2] 97 a9 [2] 80 a2 [2] 9b ec [2] a6 }

  condition:
    any of them
}