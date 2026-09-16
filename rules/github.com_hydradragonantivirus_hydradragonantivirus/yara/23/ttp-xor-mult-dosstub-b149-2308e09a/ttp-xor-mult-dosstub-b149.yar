rule TTP_XOR_MULT_DOSStub_b149 {
  strings:
    $key_b149 = { e5 21 [2] 91 39 [2] d6 3b [2] 91 2a [2] df 26 [2] d3 2c [2] c4 27 [2] df 69 [2] e2 }

  condition:
    any of them
}