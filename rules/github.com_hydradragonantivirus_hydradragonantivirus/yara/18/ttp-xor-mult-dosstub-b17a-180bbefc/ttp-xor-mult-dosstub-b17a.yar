rule TTP_XOR_MULT_DOSStub_b17a {
  strings:
    $key_b17a = { e5 12 [2] 91 0a [2] d6 08 [2] 91 19 [2] df 15 [2] d3 1f [2] c4 14 [2] df 5a [2] e2 }

  condition:
    any of them
}