rule TTP_XOR_MULT_DOSStub_b05d {
  strings:
    $key_b05d = { e4 35 [2] 90 2d [2] d7 2f [2] 90 3e [2] de 32 [2] d2 38 [2] c5 33 [2] de 7d [2] e3 }

  condition:
    any of them
}