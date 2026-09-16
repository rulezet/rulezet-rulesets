rule TTP_XOR_MULT_DOSStub_b1fa {
  strings:
    $key_b1fa = { e5 92 [2] 91 8a [2] d6 88 [2] 91 99 [2] df 95 [2] d3 9f [2] c4 94 [2] df da [2] e2 }

  condition:
    any of them
}