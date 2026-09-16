rule TTP_XOR_MULT_DOSStub_b168 {
  strings:
    $key_b168 = { e5 00 [2] 91 18 [2] d6 1a [2] 91 0b [2] df 07 [2] d3 0d [2] c4 06 [2] df 48 [2] e2 }

  condition:
    any of them
}