rule TTP_XOR_MULT_DOSStub_b1f5 {
  strings:
    $key_b1f5 = { e5 9d [2] 91 85 [2] d6 87 [2] 91 96 [2] df 9a [2] d3 90 [2] c4 9b [2] df d5 [2] e2 }

  condition:
    any of them
}