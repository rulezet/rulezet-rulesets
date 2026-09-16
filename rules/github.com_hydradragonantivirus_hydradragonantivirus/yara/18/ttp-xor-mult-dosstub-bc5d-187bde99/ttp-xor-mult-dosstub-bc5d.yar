rule TTP_XOR_MULT_DOSStub_bc5d {
  strings:
    $key_bc5d = { e8 35 [2] 9c 2d [2] db 2f [2] 9c 3e [2] d2 32 [2] de 38 [2] c9 33 [2] d2 7d [2] ef }

  condition:
    any of them
}