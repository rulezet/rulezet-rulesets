rule TTP_XOR_MULT_DOSStub_39ca {
  strings:
    $key_39ca = { 6d a2 [2] 19 ba [2] 5e b8 [2] 19 a9 [2] 57 a5 [2] 5b af [2] 4c a4 [2] 57 ea [2] 6a }

  condition:
    any of them
}