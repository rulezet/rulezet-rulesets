rule TTP_XOR_MULT_DOSStub_bc52 {
  strings:
    $key_bc52 = { e8 3a [2] 9c 22 [2] db 20 [2] 9c 31 [2] d2 3d [2] de 37 [2] c9 3c [2] d2 72 [2] ef }

  condition:
    any of them
}