rule TTP_XOR_MULT_DOSStub_bc4f {
  strings:
    $key_bc4f = { e8 27 [2] 9c 3f [2] db 3d [2] 9c 2c [2] d2 20 [2] de 2a [2] c9 21 [2] d2 6f [2] ef }

  condition:
    any of them
}