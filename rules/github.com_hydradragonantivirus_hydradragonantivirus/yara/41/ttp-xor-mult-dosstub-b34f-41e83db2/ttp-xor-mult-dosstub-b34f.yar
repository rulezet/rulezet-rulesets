rule TTP_XOR_MULT_DOSStub_b34f {
  strings:
    $key_b34f = { e7 27 [2] 93 3f [2] d4 3d [2] 93 2c [2] dd 20 [2] d1 2a [2] c6 21 [2] dd 6f [2] e0 }

  condition:
    any of them
}