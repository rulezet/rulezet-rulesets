rule TTP_XOR_MULT_DOSStub_b16a {
  strings:
    $key_b16a = { e5 02 [2] 91 1a [2] d6 18 [2] 91 09 [2] df 05 [2] d3 0f [2] c4 04 [2] df 4a [2] e2 }

  condition:
    any of them
}