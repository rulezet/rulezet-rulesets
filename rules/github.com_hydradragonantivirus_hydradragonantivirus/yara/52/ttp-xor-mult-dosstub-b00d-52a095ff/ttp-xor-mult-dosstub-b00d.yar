rule TTP_XOR_MULT_DOSStub_b00d {
  strings:
    $key_b00d = { e4 65 [2] 90 7d [2] d7 7f [2] 90 6e [2] de 62 [2] d2 68 [2] c5 63 [2] de 2d [2] e3 }

  condition:
    any of them
}