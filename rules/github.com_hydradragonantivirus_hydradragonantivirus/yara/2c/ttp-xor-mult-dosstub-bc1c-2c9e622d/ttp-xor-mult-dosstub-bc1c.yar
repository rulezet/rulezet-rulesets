rule TTP_XOR_MULT_DOSStub_bc1c {
  strings:
    $key_bc1c = { e8 74 [2] 9c 6c [2] db 6e [2] 9c 7f [2] d2 73 [2] de 79 [2] c9 72 [2] d2 3c [2] ef }

  condition:
    any of them
}