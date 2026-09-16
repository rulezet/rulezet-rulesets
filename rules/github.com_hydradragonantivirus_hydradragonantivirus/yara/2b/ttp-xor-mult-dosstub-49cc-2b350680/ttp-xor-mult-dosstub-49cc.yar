rule TTP_XOR_MULT_DOSStub_49cc {
  strings:
    $key_49cc = { 1d a4 [2] 69 bc [2] 2e be [2] 69 af [2] 27 a3 [2] 2b a9 [2] 3c a2 [2] 27 ec [2] 1a }

  condition:
    any of them
}