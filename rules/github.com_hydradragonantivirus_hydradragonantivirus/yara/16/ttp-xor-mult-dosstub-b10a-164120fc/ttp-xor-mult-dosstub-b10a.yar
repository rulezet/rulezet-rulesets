rule TTP_XOR_MULT_DOSStub_b10a {
  strings:
    $key_b10a = { e5 62 [2] 91 7a [2] d6 78 [2] 91 69 [2] df 65 [2] d3 6f [2] c4 64 [2] df 2a [2] e2 }

  condition:
    any of them
}