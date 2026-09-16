rule TTP_XOR_MULT_DOSStub_58cc {
  strings:
    $key_58cc = { 0c a4 [2] 78 bc [2] 3f be [2] 78 af [2] 36 a3 [2] 3a a9 [2] 2d a2 [2] 36 ec [2] 0b }

  condition:
    any of them
}