rule TTP_XOR_MULT_DOSStub_bc5f {
  strings:
    $key_bc5f = { e8 37 [2] 9c 2f [2] db 2d [2] 9c 3c [2] d2 30 [2] de 3a [2] c9 31 [2] d2 7f [2] ef }

  condition:
    any of them
}