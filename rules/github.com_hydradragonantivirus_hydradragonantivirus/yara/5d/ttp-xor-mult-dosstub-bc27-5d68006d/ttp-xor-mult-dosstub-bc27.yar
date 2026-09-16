rule TTP_XOR_MULT_DOSStub_bc27 {
  strings:
    $key_bc27 = { e8 4f [2] 9c 57 [2] db 55 [2] 9c 44 [2] d2 48 [2] de 42 [2] c9 49 [2] d2 07 [2] ef }

  condition:
    any of them
}