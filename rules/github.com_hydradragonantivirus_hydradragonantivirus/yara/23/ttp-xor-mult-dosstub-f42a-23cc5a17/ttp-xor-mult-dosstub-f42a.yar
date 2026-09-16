rule TTP_XOR_MULT_DOSStub_f42a {
  strings:
    $key_f42a = { a0 42 [2] d4 5a [2] 93 58 [2] d4 49 [2] 9a 45 [2] 96 4f [2] 81 44 [2] 9a 0a [2] a7 }

  condition:
    any of them
}