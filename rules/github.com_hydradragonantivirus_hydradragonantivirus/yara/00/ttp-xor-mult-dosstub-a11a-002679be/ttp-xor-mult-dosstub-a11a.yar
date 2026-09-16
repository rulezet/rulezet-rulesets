rule TTP_XOR_MULT_DOSStub_a11a {
  strings:
    $key_a11a = { f5 72 [2] 81 6a [2] c6 68 [2] 81 79 [2] cf 75 [2] c3 7f [2] d4 74 [2] cf 3a [2] f2 }

  condition:
    any of them
}