rule TTP_XOR_MULT_DOSStub_b172 {
  strings:
    $key_b172 = { e5 1a [2] 91 02 [2] d6 00 [2] 91 11 [2] df 1d [2] d3 17 [2] c4 1c [2] df 52 [2] e2 }

  condition:
    any of them
}