rule TTP_XOR_MULT_DOSStub_b128 {
  strings:
    $key_b128 = { e5 40 [2] 91 58 [2] d6 5a [2] 91 4b [2] df 47 [2] d3 4d [2] c4 46 [2] df 08 [2] e2 }

  condition:
    any of them
}