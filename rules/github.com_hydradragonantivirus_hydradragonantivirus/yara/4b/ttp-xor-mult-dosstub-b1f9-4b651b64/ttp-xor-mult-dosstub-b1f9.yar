rule TTP_XOR_MULT_DOSStub_b1f9 {
  strings:
    $key_b1f9 = { e5 91 [2] 91 89 [2] d6 8b [2] 91 9a [2] df 96 [2] d3 9c [2] c4 97 [2] df d9 [2] e2 }

  condition:
    any of them
}