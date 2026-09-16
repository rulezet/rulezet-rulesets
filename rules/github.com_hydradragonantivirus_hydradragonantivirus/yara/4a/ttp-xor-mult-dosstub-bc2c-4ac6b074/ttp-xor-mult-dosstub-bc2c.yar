rule TTP_XOR_MULT_DOSStub_bc2c {
  strings:
    $key_bc2c = { e8 44 [2] 9c 5c [2] db 5e [2] 9c 4f [2] d2 43 [2] de 49 [2] c9 42 [2] d2 0c [2] ef }

  condition:
    any of them
}