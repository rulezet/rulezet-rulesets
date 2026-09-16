rule TTP_XOR_MULT_DOSStub_f445 {
  strings:
    $key_f445 = { a0 2d [2] d4 35 [2] 93 37 [2] d4 26 [2] 9a 2a [2] 96 20 [2] 81 2b [2] 9a 65 [2] a7 }

  condition:
    any of them
}