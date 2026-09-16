rule TTP_XOR_MULT_DOSStub_f4cc {
  strings:
    $key_f4cc = { a0 a4 [2] d4 bc [2] 93 be [2] d4 af [2] 9a a3 [2] 96 a9 [2] 81 a2 [2] 9a ec [2] a7 }

  condition:
    any of them
}