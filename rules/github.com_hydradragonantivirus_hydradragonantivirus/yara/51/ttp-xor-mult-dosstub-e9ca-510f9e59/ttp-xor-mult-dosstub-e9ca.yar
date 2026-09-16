rule TTP_XOR_MULT_DOSStub_e9ca {
  strings:
    $key_e9ca = { bd a2 [2] c9 ba [2] 8e b8 [2] c9 a9 [2] 87 a5 [2] 8b af [2] 9c a4 [2] 87 ea [2] ba }

  condition:
    any of them
}