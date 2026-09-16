rule TTP_XOR_MULT_DOSStub_62cc {
  strings:
    $key_62cc = { 36 a4 [2] 42 bc [2] 05 be [2] 42 af [2] 0c a3 [2] 00 a9 [2] 17 a2 [2] 0c ec [2] 31 }

  condition:
    any of them
}