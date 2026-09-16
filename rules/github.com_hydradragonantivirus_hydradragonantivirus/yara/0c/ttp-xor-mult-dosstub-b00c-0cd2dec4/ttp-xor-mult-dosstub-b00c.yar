rule TTP_XOR_MULT_DOSStub_b00c {
  strings:
    $key_b00c = { e4 64 [2] 90 7c [2] d7 7e [2] 90 6f [2] de 63 [2] d2 69 [2] c5 62 [2] de 2c [2] e3 }

  condition:
    any of them
}