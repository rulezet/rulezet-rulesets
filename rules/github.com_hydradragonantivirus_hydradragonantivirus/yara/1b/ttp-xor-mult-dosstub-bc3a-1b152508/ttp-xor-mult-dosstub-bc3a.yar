rule TTP_XOR_MULT_DOSStub_bc3a {
  strings:
    $key_bc3a = { e8 52 [2] 9c 4a [2] db 48 [2] 9c 59 [2] d2 55 [2] de 5f [2] c9 54 [2] d2 1a [2] ef }

  condition:
    any of them
}