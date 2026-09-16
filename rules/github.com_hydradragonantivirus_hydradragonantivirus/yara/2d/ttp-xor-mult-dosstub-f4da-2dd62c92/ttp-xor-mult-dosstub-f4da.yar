rule TTP_XOR_MULT_DOSStub_f4da {
  strings:
    $key_f4da = { a0 b2 [2] d4 aa [2] 93 a8 [2] d4 b9 [2] 9a b5 [2] 96 bf [2] 81 b4 [2] 9a fa [2] a7 }

  condition:
    any of them
}