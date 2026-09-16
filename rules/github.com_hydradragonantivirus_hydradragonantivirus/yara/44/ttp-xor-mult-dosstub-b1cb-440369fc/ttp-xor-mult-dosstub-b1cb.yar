rule TTP_XOR_MULT_DOSStub_b1cb {
  strings:
    $key_b1cb = { e5 a3 [2] 91 bb [2] d6 b9 [2] 91 a8 [2] df a4 [2] d3 ae [2] c4 a5 [2] df eb [2] e2 }

  condition:
    any of them
}