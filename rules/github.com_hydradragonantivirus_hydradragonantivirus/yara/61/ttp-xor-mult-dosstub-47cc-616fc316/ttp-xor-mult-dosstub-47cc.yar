rule TTP_XOR_MULT_DOSStub_47cc {
  strings:
    $key_47cc = { 13 a4 [2] 67 bc [2] 20 be [2] 67 af [2] 29 a3 [2] 25 a9 [2] 32 a2 [2] 29 ec [2] 14 }

  condition:
    any of them
}