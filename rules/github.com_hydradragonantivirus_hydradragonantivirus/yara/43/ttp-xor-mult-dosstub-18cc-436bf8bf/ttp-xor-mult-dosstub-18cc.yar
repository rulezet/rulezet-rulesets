rule TTP_XOR_MULT_DOSStub_18cc {
  strings:
    $key_18cc = { 4c a4 [2] 38 bc [2] 7f be [2] 38 af [2] 76 a3 [2] 7a a9 [2] 6d a2 [2] 76 ec [2] 4b }

  condition:
    any of them
}