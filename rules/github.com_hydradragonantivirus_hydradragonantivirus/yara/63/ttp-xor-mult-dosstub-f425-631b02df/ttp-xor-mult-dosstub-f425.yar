rule TTP_XOR_MULT_DOSStub_f425 {
  strings:
    $key_f425 = { a0 4d [2] d4 55 [2] 93 57 [2] d4 46 [2] 9a 4a [2] 96 40 [2] 81 4b [2] 9a 05 [2] a7 }

  condition:
    any of them
}