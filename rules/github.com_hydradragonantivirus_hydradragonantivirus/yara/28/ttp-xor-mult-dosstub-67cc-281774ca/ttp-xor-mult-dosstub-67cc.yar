rule TTP_XOR_MULT_DOSStub_67cc {
  strings:
    $key_67cc = { 33 a4 [2] 47 bc [2] 00 be [2] 47 af [2] 09 a3 [2] 05 a9 [2] 12 a2 [2] 09 ec [2] 34 }

  condition:
    any of them
}