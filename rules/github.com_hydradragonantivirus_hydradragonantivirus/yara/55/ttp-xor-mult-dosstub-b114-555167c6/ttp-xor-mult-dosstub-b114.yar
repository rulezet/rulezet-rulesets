rule TTP_XOR_MULT_DOSStub_b114 {
  strings:
    $key_b114 = { e5 7c [2] 91 64 [2] d6 66 [2] 91 77 [2] df 7b [2] d3 71 [2] c4 7a [2] df 34 [2] e2 }

  condition:
    any of them
}