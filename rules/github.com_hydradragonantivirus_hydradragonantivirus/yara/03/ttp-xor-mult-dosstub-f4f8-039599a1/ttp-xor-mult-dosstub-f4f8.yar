rule TTP_XOR_MULT_DOSStub_f4f8 {
  strings:
    $key_f4f8 = { a0 90 [2] d4 88 [2] 93 8a [2] d4 9b [2] 9a 97 [2] 96 9d [2] 81 96 [2] 9a d8 [2] a7 }

  condition:
    any of them
}