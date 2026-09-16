rule TTP_XOR_MULT_DOSStub_56cc {
  strings:
    $key_56cc = { 02 a4 [2] 76 bc [2] 31 be [2] 76 af [2] 38 a3 [2] 34 a9 [2] 23 a2 [2] 38 ec [2] 05 }

  condition:
    any of them
}