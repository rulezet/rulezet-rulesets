rule TTP_XOR_MULT_DOSStub_f4e4 {
  strings:
    $key_f4e4 = { a0 8c [2] d4 94 [2] 93 96 [2] d4 87 [2] 9a 8b [2] 96 81 [2] 81 8a [2] 9a c4 [2] a7 }

  condition:
    any of them
}