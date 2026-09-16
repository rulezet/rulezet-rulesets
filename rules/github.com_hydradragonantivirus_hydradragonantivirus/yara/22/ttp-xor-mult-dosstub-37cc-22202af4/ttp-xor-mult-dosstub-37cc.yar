rule TTP_XOR_MULT_DOSStub_37cc {
  strings:
    $key_37cc = { 63 a4 [2] 17 bc [2] 50 be [2] 17 af [2] 59 a3 [2] 55 a9 [2] 42 a2 [2] 59 ec [2] 64 }

  condition:
    any of them
}