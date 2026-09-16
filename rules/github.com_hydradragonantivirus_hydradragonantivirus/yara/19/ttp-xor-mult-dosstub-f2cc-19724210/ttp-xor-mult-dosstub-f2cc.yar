rule TTP_XOR_MULT_DOSStub_f2cc {
  strings:
    $key_f2cc = { a6 a4 [2] d2 bc [2] 95 be [2] d2 af [2] 9c a3 [2] 90 a9 [2] 87 a2 [2] 9c ec [2] a1 }

  condition:
    any of them
}