rule TTP_XOR_MULT_DOSStub_a13a {
  strings:
    $key_a13a = { f5 52 [2] 81 4a [2] c6 48 [2] 81 59 [2] cf 55 [2] c3 5f [2] d4 54 [2] cf 1a [2] f2 }

  condition:
    any of them
}