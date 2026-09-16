rule TTP_XOR_MULT_DOSStub_b132 {
  strings:
    $key_b132 = { e5 5a [2] 91 42 [2] d6 40 [2] 91 51 [2] df 5d [2] d3 57 [2] c4 5c [2] df 12 [2] e2 }

  condition:
    any of them
}