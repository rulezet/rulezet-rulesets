rule TTP_XOR_MULT_DOSStub_20cc {
  strings:
    $key_20cc = { 74 a4 [2] 00 bc [2] 47 be [2] 00 af [2] 4e a3 [2] 42 a9 [2] 55 a2 [2] 4e ec [2] 73 }

  condition:
    any of them
}