rule TTP_XOR_MULT_DOSStub_bc25 {
  strings:
    $key_bc25 = { e8 4d [2] 9c 55 [2] db 57 [2] 9c 46 [2] d2 4a [2] de 40 [2] c9 4b [2] d2 05 [2] ef }

  condition:
    any of them
}