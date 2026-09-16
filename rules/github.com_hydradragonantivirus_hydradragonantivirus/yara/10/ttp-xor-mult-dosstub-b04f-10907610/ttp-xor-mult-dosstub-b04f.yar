rule TTP_XOR_MULT_DOSStub_b04f {
  strings:
    $key_b04f = { e4 27 [2] 90 3f [2] d7 3d [2] 90 2c [2] de 20 [2] d2 2a [2] c5 21 [2] de 6f [2] e3 }

  condition:
    any of them
}