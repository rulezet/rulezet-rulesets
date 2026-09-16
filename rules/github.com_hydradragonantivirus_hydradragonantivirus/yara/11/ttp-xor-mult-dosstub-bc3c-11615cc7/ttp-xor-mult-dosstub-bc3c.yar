rule TTP_XOR_MULT_DOSStub_bc3c {
  strings:
    $key_bc3c = { e8 54 [2] 9c 4c [2] db 4e [2] 9c 5f [2] d2 53 [2] de 59 [2] c9 52 [2] d2 1c [2] ef }

  condition:
    any of them
}