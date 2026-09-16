rule TTP_XOR_MULT_DOSStub_f45a {
  strings:
    $key_f45a = { a0 32 [2] d4 2a [2] 93 28 [2] d4 39 [2] 9a 35 [2] 96 3f [2] 81 34 [2] 9a 7a [2] a7 }

  condition:
    any of them
}