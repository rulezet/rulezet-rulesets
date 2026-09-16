rule TTP_XOR_MULT_DOSStub_39cc {
  strings:
    $key_39cc = { 6d a4 [2] 19 bc [2] 5e be [2] 19 af [2] 57 a3 [2] 5b a9 [2] 4c a2 [2] 57 ec [2] 6a }

  condition:
    any of them
}