rule TTP_XOR_MULT_DOSStub_b05f {
  strings:
    $key_b05f = { e4 37 [2] 90 2f [2] d7 2d [2] 90 3c [2] de 30 [2] d2 3a [2] c5 31 [2] de 7f [2] e3 }

  condition:
    any of them
}