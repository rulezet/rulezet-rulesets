rule TTP_XOR_MULT_DOSStub_b130 {
  strings:
    $key_b130 = { e5 58 [2] 91 40 [2] d6 42 [2] 91 53 [2] df 5f [2] d3 55 [2] c4 5e [2] df 10 [2] e2 }

  condition:
    any of them
}