rule TTP_XOR_MULT_DOSStub_b134 {
  strings:
    $key_b134 = { e5 5c [2] 91 44 [2] d6 46 [2] 91 57 [2] df 5b [2] d3 51 [2] c4 5a [2] df 14 [2] e2 }

  condition:
    any of them
}