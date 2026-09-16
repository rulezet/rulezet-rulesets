rule TTP_XOR_MULT_DOSStub_b13a {
  strings:
    $key_b13a = { e5 52 [2] 91 4a [2] d6 48 [2] 91 59 [2] df 55 [2] d3 5f [2] c4 54 [2] df 1a [2] e2 }

  condition:
    any of them
}