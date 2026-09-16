rule TTP_XOR_MULT_DOSStub_bc44 {
  strings:
    $key_bc44 = { e8 2c [2] 9c 34 [2] db 36 [2] 9c 27 [2] d2 2b [2] de 21 [2] c9 2a [2] d2 64 [2] ef }

  condition:
    any of them
}