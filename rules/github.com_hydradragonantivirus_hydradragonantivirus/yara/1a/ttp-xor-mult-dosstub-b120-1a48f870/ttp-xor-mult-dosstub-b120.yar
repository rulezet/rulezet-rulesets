rule TTP_XOR_MULT_DOSStub_b120 {
  strings:
    $key_b120 = { e5 48 [2] 91 50 [2] d6 52 [2] 91 43 [2] df 4f [2] d3 45 [2] c4 4e [2] df 00 [2] e2 }

  condition:
    any of them
}