rule TTP_XOR_MULT_DOSStub_b139 {
  strings:
    $key_b139 = { e5 51 [2] 91 49 [2] d6 4b [2] 91 5a [2] df 56 [2] d3 5c [2] c4 57 [2] df 19 [2] e2 }

  condition:
    any of them
}