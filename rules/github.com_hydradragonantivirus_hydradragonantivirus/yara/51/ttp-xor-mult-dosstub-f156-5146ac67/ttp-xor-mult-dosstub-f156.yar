rule TTP_XOR_MULT_DOSStub_f156 {
  strings:
    $key_f156 = { a5 3e [2] d1 26 [2] 96 24 [2] d1 35 [2] 9f 39 [2] 93 33 [2] 84 38 [2] 9f 76 [2] a2 }

  condition:
    any of them
}