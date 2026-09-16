rule TTP_XOR_MULT_DOSStub_b043 {
  strings:
    $key_b043 = { e4 2b [2] 90 33 [2] d7 31 [2] 90 20 [2] de 2c [2] d2 26 [2] c5 2d [2] de 63 [2] e3 }

  condition:
    any of them
}