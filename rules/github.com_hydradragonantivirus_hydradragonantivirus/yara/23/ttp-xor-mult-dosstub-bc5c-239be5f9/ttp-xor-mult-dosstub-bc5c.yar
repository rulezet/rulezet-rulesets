rule TTP_XOR_MULT_DOSStub_bc5c {
  strings:
    $key_bc5c = { e8 34 [2] 9c 2c [2] db 2e [2] 9c 3f [2] d2 33 [2] de 39 [2] c9 32 [2] d2 7c [2] ef }

  condition:
    any of them
}