rule TTP_XOR_MULT_DOSStub_60cc {
  strings:
    $key_60cc = { 34 a4 [2] 40 bc [2] 07 be [2] 40 af [2] 0e a3 [2] 02 a9 [2] 15 a2 [2] 0e ec [2] 33 }

  condition:
    any of them
}