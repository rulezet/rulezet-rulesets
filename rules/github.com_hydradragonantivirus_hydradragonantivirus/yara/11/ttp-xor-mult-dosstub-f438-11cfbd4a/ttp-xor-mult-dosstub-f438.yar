rule TTP_XOR_MULT_DOSStub_f438 {
  strings:
    $key_f438 = { a0 50 [2] d4 48 [2] 93 4a [2] d4 5b [2] 9a 57 [2] 96 5d [2] 81 56 [2] 9a 18 [2] a7 }

  condition:
    any of them
}