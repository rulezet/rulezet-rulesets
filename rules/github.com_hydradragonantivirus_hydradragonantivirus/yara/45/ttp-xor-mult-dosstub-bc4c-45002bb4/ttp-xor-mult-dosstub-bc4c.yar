rule TTP_XOR_MULT_DOSStub_bc4c {
  strings:
    $key_bc4c = { e8 24 [2] 9c 3c [2] db 3e [2] 9c 2f [2] d2 23 [2] de 29 [2] c9 22 [2] d2 6c [2] ef }

  condition:
    any of them
}