rule TTP_XOR_MULT_DOSStub_b11a {
  strings:
    $key_b11a = { e5 72 [2] 91 6a [2] d6 68 [2] 91 79 [2] df 75 [2] d3 7f [2] c4 74 [2] df 3a [2] e2 }

  condition:
    any of them
}