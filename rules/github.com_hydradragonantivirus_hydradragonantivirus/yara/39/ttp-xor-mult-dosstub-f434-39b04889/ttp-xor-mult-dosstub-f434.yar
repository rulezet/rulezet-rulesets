rule TTP_XOR_MULT_DOSStub_f434 {
  strings:
    $key_f434 = { a0 5c [2] d4 44 [2] 93 46 [2] d4 57 [2] 9a 5b [2] 96 51 [2] 81 5a [2] 9a 14 [2] a7 }

  condition:
    any of them
}