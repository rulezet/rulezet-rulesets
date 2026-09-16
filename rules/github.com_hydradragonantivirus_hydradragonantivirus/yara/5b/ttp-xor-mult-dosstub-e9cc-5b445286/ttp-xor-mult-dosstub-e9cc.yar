rule TTP_XOR_MULT_DOSStub_e9cc {
  strings:
    $key_e9cc = { bd a4 [2] c9 bc [2] 8e be [2] c9 af [2] 87 a3 [2] 8b a9 [2] 9c a2 [2] 87 ec [2] ba }

  condition:
    any of them
}