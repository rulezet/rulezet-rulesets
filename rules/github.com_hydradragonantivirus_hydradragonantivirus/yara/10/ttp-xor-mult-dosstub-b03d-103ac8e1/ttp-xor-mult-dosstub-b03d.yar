rule TTP_XOR_MULT_DOSStub_b03d {
  strings:
    $key_b03d = { e4 55 [2] 90 4d [2] d7 4f [2] 90 5e [2] de 52 [2] d2 58 [2] c5 53 [2] de 1d [2] e3 }

  condition:
    any of them
}