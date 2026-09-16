rule TTP_XOR_MULT_DOSStub_f4e7 {
  strings:
    $key_f4e7 = { a0 8f [2] d4 97 [2] 93 95 [2] d4 84 [2] 9a 88 [2] 96 82 [2] 81 89 [2] 9a c7 [2] a7 }

  condition:
    any of them
}