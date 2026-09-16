rule TTP_XOR_MULT_DOSStub_b159 {
  strings:
    $key_b159 = { e5 31 [2] 91 29 [2] d6 2b [2] 91 3a [2] df 36 [2] d3 3c [2] c4 37 [2] df 79 [2] e2 }

  condition:
    any of them
}