rule TTP_XOR_MULT_DOSStub_69cc {
  strings:
    $key_69cc = { 3d a4 [2] 49 bc [2] 0e be [2] 49 af [2] 07 a3 [2] 0b a9 [2] 1c a2 [2] 07 ec [2] 3a }

  condition:
    any of them
}