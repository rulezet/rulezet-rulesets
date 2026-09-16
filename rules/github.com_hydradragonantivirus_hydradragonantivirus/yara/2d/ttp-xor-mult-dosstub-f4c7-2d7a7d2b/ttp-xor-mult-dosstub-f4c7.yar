rule TTP_XOR_MULT_DOSStub_f4c7 {
  strings:
    $key_f4c7 = { a0 af [2] d4 b7 [2] 93 b5 [2] d4 a4 [2] 9a a8 [2] 96 a2 [2] 81 a9 [2] 9a e7 [2] a7 }

  condition:
    any of them
}