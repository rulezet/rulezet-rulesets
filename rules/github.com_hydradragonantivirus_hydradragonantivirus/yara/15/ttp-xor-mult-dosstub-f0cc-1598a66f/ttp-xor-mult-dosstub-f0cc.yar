rule TTP_XOR_MULT_DOSStub_f0cc {
  strings:
    $key_f0cc = { a4 a4 [2] d0 bc [2] 97 be [2] d0 af [2] 9e a3 [2] 92 a9 [2] 85 a2 [2] 9e ec [2] a3 }

  condition:
    any of them
}