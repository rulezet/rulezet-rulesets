rule TTP_XOR_MULT_DOSStub_b14a {
  strings:
    $key_b14a = { e5 22 [2] 91 3a [2] d6 38 [2] 91 29 [2] df 25 [2] d3 2f [2] c4 24 [2] df 6a [2] e2 }

  condition:
    any of them
}