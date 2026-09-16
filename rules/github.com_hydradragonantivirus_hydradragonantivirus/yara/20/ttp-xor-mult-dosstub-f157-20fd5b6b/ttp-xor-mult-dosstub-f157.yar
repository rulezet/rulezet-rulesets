rule TTP_XOR_MULT_DOSStub_f157 {
  strings:
    $key_f157 = { a5 3f [2] d1 27 [2] 96 25 [2] d1 34 [2] 9f 38 [2] 93 32 [2] 84 39 [2] 9f 77 [2] a2 }

  condition:
    any of them
}