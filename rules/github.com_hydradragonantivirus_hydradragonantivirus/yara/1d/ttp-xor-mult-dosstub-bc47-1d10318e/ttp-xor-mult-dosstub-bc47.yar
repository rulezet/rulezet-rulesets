rule TTP_XOR_MULT_DOSStub_bc47 {
  strings:
    $key_bc47 = { e8 2f [2] 9c 37 [2] db 35 [2] 9c 24 [2] d2 28 [2] de 22 [2] c9 29 [2] d2 67 [2] ef }

  condition:
    any of them
}