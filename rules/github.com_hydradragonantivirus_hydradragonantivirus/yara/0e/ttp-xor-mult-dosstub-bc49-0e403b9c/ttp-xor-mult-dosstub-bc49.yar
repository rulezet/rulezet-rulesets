rule TTP_XOR_MULT_DOSStub_bc49 {
  strings:
    $key_bc49 = { e8 21 [2] 9c 39 [2] db 3b [2] 9c 2a [2] d2 26 [2] de 2c [2] c9 27 [2] d2 69 [2] ef }

  condition:
    any of them
}