rule TTP_XOR_MULT_DOSStub_bc2a {
  strings:
    $key_bc2a = { e8 42 [2] 9c 5a [2] db 58 [2] 9c 49 [2] d2 45 [2] de 4f [2] c9 44 [2] d2 0a [2] ef }

  condition:
    any of them
}