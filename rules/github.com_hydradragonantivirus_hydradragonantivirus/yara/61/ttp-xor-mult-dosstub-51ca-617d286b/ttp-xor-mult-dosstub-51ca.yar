rule TTP_XOR_MULT_DOSStub_51ca {
  strings:
    $key_51ca = { 05 a2 [2] 71 ba [2] 36 b8 [2] 71 a9 [2] 3f a5 [2] 33 af [2] 24 a4 [2] 3f ea [2] 02 }

  condition:
    any of them
}