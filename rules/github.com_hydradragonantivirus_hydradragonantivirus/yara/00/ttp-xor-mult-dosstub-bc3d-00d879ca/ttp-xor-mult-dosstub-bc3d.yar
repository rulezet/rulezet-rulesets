rule TTP_XOR_MULT_DOSStub_bc3d {
  strings:
    $key_bc3d = { e8 55 [2] 9c 4d [2] db 4f [2] 9c 5e [2] d2 52 [2] de 58 [2] c9 53 [2] d2 1d [2] ef }

  condition:
    any of them
}