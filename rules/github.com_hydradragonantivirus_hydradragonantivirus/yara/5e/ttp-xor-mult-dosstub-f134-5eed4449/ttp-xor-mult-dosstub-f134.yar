rule TTP_XOR_MULT_DOSStub_f134 {
  strings:
    $key_f134 = { a5 5c [2] d1 44 [2] 96 46 [2] d1 57 [2] 9f 5b [2] 93 51 [2] 84 5a [2] 9f 14 [2] a2 }

  condition:
    any of them
}