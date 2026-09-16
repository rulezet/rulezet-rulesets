rule TTP_XOR_MULT_DOSStub_b1f4 {
  strings:
    $key_b1f4 = { e5 9c [2] 91 84 [2] d6 86 [2] 91 97 [2] df 9b [2] d3 91 [2] c4 9a [2] df d4 [2] e2 }

  condition:
    any of them
}