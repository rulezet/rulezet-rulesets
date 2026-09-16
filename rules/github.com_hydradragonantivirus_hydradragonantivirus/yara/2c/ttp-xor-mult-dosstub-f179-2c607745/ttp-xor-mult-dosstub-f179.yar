rule TTP_XOR_MULT_DOSStub_f179 {
  strings:
    $key_f179 = { a5 11 [2] d1 09 [2] 96 0b [2] d1 1a [2] 9f 16 [2] 93 1c [2] 84 17 [2] 9f 59 [2] a2 }

  condition:
    any of them
}