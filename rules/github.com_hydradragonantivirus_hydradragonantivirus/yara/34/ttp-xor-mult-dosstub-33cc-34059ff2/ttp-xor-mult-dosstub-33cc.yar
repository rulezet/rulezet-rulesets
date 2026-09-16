rule TTP_XOR_MULT_DOSStub_33cc {
  strings:
    $key_33cc = { 67 a4 [2] 13 bc [2] 54 be [2] 13 af [2] 5d a3 [2] 51 a9 [2] 46 a2 [2] 5d ec [2] 60 }

  condition:
    any of them
}