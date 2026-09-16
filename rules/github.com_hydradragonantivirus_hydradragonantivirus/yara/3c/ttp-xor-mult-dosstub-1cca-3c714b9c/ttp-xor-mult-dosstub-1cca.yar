rule TTP_XOR_MULT_DOSStub_1cca {
  strings:
    $key_1cca = { 48 a2 [2] 3c ba [2] 7b b8 [2] 3c a9 [2] 72 a5 [2] 7e af [2] 69 a4 [2] 72 ea [2] 4f }

  condition:
    any of them
}