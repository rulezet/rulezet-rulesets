rule TTP_XOR_MULT_DOSStub_b00f {
  strings:
    $key_b00f = { e4 67 [2] 90 7f [2] d7 7d [2] 90 6c [2] de 60 [2] d2 6a [2] c5 61 [2] de 2f [2] e3 }

  condition:
    any of them
}