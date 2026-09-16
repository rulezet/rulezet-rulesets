rule TTP_XOR_MULT_DOSStub_f457 {
  strings:
    $key_f457 = { a0 3f [2] d4 27 [2] 93 25 [2] d4 34 [2] 9a 38 [2] 96 32 [2] 81 39 [2] 9a 77 [2] a7 }

  condition:
    any of them
}