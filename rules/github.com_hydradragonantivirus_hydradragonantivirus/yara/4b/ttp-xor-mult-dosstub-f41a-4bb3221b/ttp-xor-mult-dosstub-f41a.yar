rule TTP_XOR_MULT_DOSStub_f41a {
  strings:
    $key_f41a = { a0 72 [2] d4 6a [2] 93 68 [2] d4 79 [2] 9a 75 [2] 96 7f [2] 81 74 [2] 9a 3a [2] a7 }

  condition:
    any of them
}