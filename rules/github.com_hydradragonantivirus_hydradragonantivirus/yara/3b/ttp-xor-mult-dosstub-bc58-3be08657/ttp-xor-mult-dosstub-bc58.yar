rule TTP_XOR_MULT_DOSStub_bc58 {
  strings:
    $key_bc58 = { e8 30 [2] 9c 28 [2] db 2a [2] 9c 3b [2] d2 37 [2] de 3d [2] c9 36 [2] d2 78 [2] ef }

  condition:
    any of them
}