rule TTP_XOR_MULT_DOSStub_bc1d {
  strings:
    $key_bc1d = { e8 75 [2] 9c 6d [2] db 6f [2] 9c 7e [2] d2 72 [2] de 78 [2] c9 73 [2] d2 3d [2] ef }

  condition:
    any of them
}