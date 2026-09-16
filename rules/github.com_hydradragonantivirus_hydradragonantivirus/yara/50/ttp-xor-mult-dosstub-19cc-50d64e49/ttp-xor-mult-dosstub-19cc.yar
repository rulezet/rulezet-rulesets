rule TTP_XOR_MULT_DOSStub_19cc {
  strings:
    $key_19cc = { 4d a4 [2] 39 bc [2] 7e be [2] 39 af [2] 77 a3 [2] 7b a9 [2] 6c a2 [2] 77 ec [2] 4a }

  condition:
    any of them
}