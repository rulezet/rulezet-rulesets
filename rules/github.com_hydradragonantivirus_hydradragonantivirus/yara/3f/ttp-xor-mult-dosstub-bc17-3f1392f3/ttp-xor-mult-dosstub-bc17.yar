rule TTP_XOR_MULT_DOSStub_bc17 {
  strings:
    $key_bc17 = { e8 7f [2] 9c 67 [2] db 65 [2] 9c 74 [2] d2 78 [2] de 72 [2] c9 79 [2] d2 37 [2] ef }

  condition:
    any of them
}