rule TTP_XOR_MULT_DOSStub_49ca {
  strings:
    $key_49ca = { 1d a2 [2] 69 ba [2] 2e b8 [2] 69 a9 [2] 27 a5 [2] 2b af [2] 3c a4 [2] 27 ea [2] 1a }

  condition:
    any of them
}