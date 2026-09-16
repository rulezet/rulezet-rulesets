rule TTP_XOR_MULT_DOSStub_f149 {
  strings:
    $key_f149 = { a5 21 [2] d1 39 [2] 96 3b [2] d1 2a [2] 9f 26 [2] 93 2c [2] 84 27 [2] 9f 69 [2] a2 }

  condition:
    any of them
}