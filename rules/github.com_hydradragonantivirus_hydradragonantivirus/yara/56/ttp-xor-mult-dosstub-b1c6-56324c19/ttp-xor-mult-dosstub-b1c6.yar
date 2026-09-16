rule TTP_XOR_MULT_DOSStub_b1c6 {
  strings:
    $key_b1c6 = { e5 ae [2] 91 b6 [2] d6 b4 [2] 91 a5 [2] df a9 [2] d3 a3 [2] c4 a8 [2] df e6 [2] e2 }

  condition:
    any of them
}