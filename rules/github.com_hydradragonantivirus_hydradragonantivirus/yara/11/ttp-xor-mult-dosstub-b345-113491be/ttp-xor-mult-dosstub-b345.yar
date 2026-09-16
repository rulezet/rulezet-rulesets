rule TTP_XOR_MULT_DOSStub_b345 {
  strings:
    $key_b345 = { e7 2d [2] 93 35 [2] d4 37 [2] 93 26 [2] dd 2a [2] d1 20 [2] c6 2b [2] dd 65 [2] e0 }

  condition:
    any of them
}