rule TTP_XOR_MULT_DOSStub_bc4d {
  strings:
    $key_bc4d = { e8 25 [2] 9c 3d [2] db 3f [2] 9c 2e [2] d2 22 [2] de 28 [2] c9 23 [2] d2 6d [2] ef }

  condition:
    any of them
}