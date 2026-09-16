rule TTP_XOR_MULT_DOSStub_b119 {
  strings:
    $key_b119 = { e5 71 [2] 91 69 [2] d6 6b [2] 91 7a [2] df 76 [2] d3 7c [2] c4 77 [2] df 39 [2] e2 }

  condition:
    any of them
}