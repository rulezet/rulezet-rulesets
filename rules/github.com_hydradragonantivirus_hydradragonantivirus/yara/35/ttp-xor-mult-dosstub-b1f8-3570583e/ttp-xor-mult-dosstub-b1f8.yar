rule TTP_XOR_MULT_DOSStub_b1f8 {
  strings:
    $key_b1f8 = { e5 90 [2] 91 88 [2] d6 8a [2] 91 9b [2] df 97 [2] d3 9d [2] c4 96 [2] df d8 [2] e2 }

  condition:
    any of them
}