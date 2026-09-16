rule TTP_XOR_MULT_DOSStub_f106 {
  strings:
    $key_f106 = { a5 6e [2] d1 76 [2] 96 74 [2] d1 65 [2] 9f 69 [2] 93 63 [2] 84 68 [2] 9f 26 [2] a2 }

  condition:
    any of them
}