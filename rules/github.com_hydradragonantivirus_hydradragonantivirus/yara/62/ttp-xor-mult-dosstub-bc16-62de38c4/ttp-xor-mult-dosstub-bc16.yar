rule TTP_XOR_MULT_DOSStub_bc16 {
  strings:
    $key_bc16 = { e8 7e [2] 9c 66 [2] db 64 [2] 9c 75 [2] d2 79 [2] de 73 [2] c9 78 [2] d2 36 [2] ef }

  condition:
    any of them
}