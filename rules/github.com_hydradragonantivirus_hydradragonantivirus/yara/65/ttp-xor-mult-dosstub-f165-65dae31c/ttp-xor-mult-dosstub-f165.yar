rule TTP_XOR_MULT_DOSStub_f165 {
  strings:
    $key_f165 = { a5 0d [2] d1 15 [2] 96 17 [2] d1 06 [2] 9f 0a [2] 93 00 [2] 84 0b [2] 9f 45 [2] a2 }

  condition:
    any of them
}