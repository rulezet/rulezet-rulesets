rule TTP_XOR_MULT_DOSStub_b01d {
  strings:
    $key_b01d = { e4 75 [2] 90 6d [2] d7 6f [2] 90 7e [2] de 72 [2] d2 78 [2] c5 73 [2] de 3d [2] e3 }

  condition:
    any of them
}